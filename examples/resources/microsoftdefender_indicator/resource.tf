resource "microsoftdefender_indicator" "example_application" {
  indicator_value = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  indicator_type  = "FileSha256"
  action          = "Allowed"

  title       = "Example application approved SHA256"
  application = "Example Application"
  description = "Example approved application release"

  severity         = "Informational"
  generate_alert   = false
  rbac_group_names = []
}

resource "microsoftdefender_indicator" "example_installer" {
  indicator_value = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
  indicator_type  = "FileSha256"
  action          = "Allowed"

  title       = "Example installer approved SHA256"
  application = "Example Application"
  description = "Example approved application installer"

  severity         = "Informational"
  generate_alert   = false
  rbac_group_names = []
}
