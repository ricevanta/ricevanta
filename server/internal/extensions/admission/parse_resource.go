package admission

// ParseResource decodes the GitOps kind Extension. It is not the package
// manifest: spec.components, files and spec.requires are invalid here.
func ParseResource(data []byte) (Resource, error) {
	root, err := decodeJSON(data, MaxResourceBytes)
	if err != nil {
		return Resource{}, err
	}
	var c checker
	r, ok := c.resource(root)
	if ok {
		c.validResource(&r)
	}
	if err := c.result(ok); err != nil {
		return Resource{}, err
	}
	return r, nil
}

func (c *checker) resource(n *node) (Resource, bool) {
	var r Resource
	if !fields(n, []string{"apiVersion", "kind", "metadata", "spec"}) {
		return r, false
	}
	apiVersion, ok := asString(n.member("apiVersion"))
	if !ok {
		return r, false
	}
	kind, ok := asString(n.member("kind"))
	if !ok {
		return r, false
	}
	c.check(apiVersion == "ricevanta.io/v1alpha1" && kind == "Extension")
	metadata := n.member("metadata")
	if !fields(metadata, []string{"name"}) {
		return r, false
	}
	if r.ID, ok = asString(metadata.member("name")); !ok {
		return r, false
	}
	spec := n.member("spec")
	if !fields(spec, []string{"version", "source", "grants", "targets", "enabled"}) {
		return r, false
	}
	if r.Version, ok = asString(spec.member("version")); !ok {
		return r, false
	}
	source := spec.member("source")
	if !fields(source, []string{"sha256"}, "url") {
		return r, false
	}
	if u := source.member("url"); u != nil {
		if r.Source.URL, ok = asString(u); !ok {
			return r, false
		}
		c.check(r.Source.URL != "")
	}
	if r.Source.SHA256, ok = c.hexDigest(source.member("sha256")); !ok {
		return r, false
	}
	if r.Targets, ok = c.targets(spec.member("targets")); !ok {
		return r, false
	}
	if r.Enabled, ok = asBool(spec.member("enabled")); !ok {
		return r, false
	}
	grants, ok := asArray(spec.member("grants"))
	if !ok {
		return r, false
	}
	r.Grants = make([]Grant, len(grants))
	for i, g := range grants {
		if r.Grants[i], ok = c.grant(g); !ok {
			return r, false
		}
	}
	return r, true
}

func (c *checker) validResource(r *Resource) {
	c.check(validID(r.ID) && validVersion(r.Version))
	c.check(r.Source.URL == "" || matches(r.Source.URL, 9, 2048, urlPattern))
	c.check(len(r.Grants) >= 1 && len(r.Grants) <= 64)
	for i := range r.Grants {
		c.validGrant(&r.Grants[i])
		for j := 0; j < i; j++ {
			c.check(!grantEqual(&r.Grants[j], &r.Grants[i]))
		}
	}
	c.validTargets(&r.Targets)
}
