# Run only on the Windows CI administrator. No credentials, token details or file content are printed.
$ErrorActionPreference = 'Stop'
$diagRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('rv-deny-mask-' + [Guid]::NewGuid().ToString('N'))
$sections = [System.Security.AccessControl.AccessControlSections]
$adminSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
function Show-RawAcl([string]$Label, $Acl) {
    $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new($Acl.GetSecurityDescriptorBinaryForm(), 0)
    $readMask = [int][System.Security.AccessControl.FileSystemRights]::Read -bor [int][System.Security.AccessControl.FileSystemRights]::Synchronize
    Write-Output ('{0}: owner={1}' -f $Label, $raw.Owner.Value)
    foreach ($ace in $raw.DiscretionaryAcl) {
        Write-Output ('{0}: type={1} flags={2} mask=0x{3:X8} sid={4} generic-read-overlap=0x{5:X8}' -f $Label, [int]$ace.AceType, [int]$ace.AceFlags, $ace.AccessMask, $ace.SecurityIdentifier.Value, ($ace.AccessMask -band $readMask))
    }
}
try {
    $rootInfo = [System.IO.Directory]::CreateDirectory($diagRoot)
    $rootAcl = [System.Security.AccessControl.DirectorySecurity]::new()
    $rootAcl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)', $sections::Access)
    $rootAcl.SetOwner($adminSid)
    [System.IO.FileSystemAclExtensions]::SetAccessControl($rootInfo, $rootAcl)
    foreach ($permission in @('D', 'DE')) {
        $parentPath = Join-Path $diagRoot $permission
        $parentInfo = [System.IO.Directory]::CreateDirectory($parentPath)
        $parentAcl = [System.IO.FileSystemAclExtensions]::GetAccessControl($parentInfo)
        $parentAcl.SetOwner($adminSid)
        [System.IO.FileSystemAclExtensions]::SetAccessControl($parentInfo, $parentAcl)
        $rule = '*S-1-5-32-545:(OI)(CI)(IO)(' + $permission + ')'
        $null = & icacls.exe $parentPath /deny $rule
        if ($LASTEXITCODE -ne 0) { throw ('icacls /deny exited {0}' -f $LASTEXITCODE) }
        Show-RawAcl ($permission + '-parent') ([System.IO.FileSystemAclExtensions]::GetAccessControl($parentInfo))
        $path = Join-Path $parentPath 'probe.bin'
        $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
        $stream = [System.IO.FileStream]::new($path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, $share)
        try {
            $stream.WriteByte(65)
            Show-RawAcl ($permission + '-child-via-create-handle') ([System.IO.FileSystemAclExtensions]::GetAccessControl($stream))
        } finally { $stream.Dispose() }
        try {
            $bytes = [System.IO.File]::ReadAllBytes($path)
            Write-Output ('{0}-read: success bytes={1}' -f $permission, $bytes.Length)
        } catch {
            Write-Output ('{0}-read: failed type={1} hresult=0x{2:X8}' -f $permission, $_.Exception.GetBaseException().GetType().Name, $_.Exception.GetBaseException().HResult)
        }
    }
} finally {
    if ([System.IO.Directory]::Exists($diagRoot)) {
        foreach ($permission in @('D', 'DE')) {
            $parentPath = Join-Path $diagRoot $permission
            if ([System.IO.Directory]::Exists($parentPath)) {
                $null = & icacls.exe $parentPath /remove:d '*S-1-5-32-545' /T /Q
                if ($LASTEXITCODE -ne 0) { throw ('diagnostic cleanup icacls exited {0}' -f $LASTEXITCODE) }
            }
        }
        [System.IO.Directory]::Delete($diagRoot, $true)
    }
}

