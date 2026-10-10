import { copyFileSync, mkdirSync, readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
export function prepareAssets(branding: string, output: string): void {
  const license = 'node_modules/@fontsource/be-vietnam-pro/LICENSE'
  if (!readFileSync(license, 'utf8').includes('SIL OPEN FONT LICENSE'))
    throw new Error('Missing OFL evidence')
  const copies = readdirSync(join(branding, 'dist/web')).map((name) => [
    join(branding, 'dist/web', name),
    name,
  ])
  copies.push(
    ...['horizontal-color.svg', 'horizontal-dark.svg'].map((name) => [
      join(branding, 'dist/svg', name),
      name,
    ]),
  )
  mkdirSync(join(output, 'brand'), { recursive: true })
  mkdirSync(join(output, 'assets'), { recursive: true })
  for (const [source, name] of copies) {
    if (!source || !name) throw new Error('Invalid asset input')
    copyFileSync(source, join(output, 'brand', name))
  }
  copyFileSync(license, join(output, 'assets/OFL-BeVietnamPro.txt'))
}
if (import.meta.main) prepareAssets('../branding', 'public')
