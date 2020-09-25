# Change Log

# 0.4.0

- Converted `vadc.deploy_workflow` workflow to Orquesta
  Contributed by Nick Maludy (Encore Technologies)
  
# 0.3.2

- Python 3 fixups
- Add explicit support for Python 2 and 3

# 0.3.1

- Minor linting fix

# 0.3.0

- vtm_add_pool now only sets nodes, unless you provide the optional params
for algorithm, monitors, and session persistence.

- You can now parse JSON or YAML strings in an `extra` parameter to apply
addition configuration when creating objects. This can be used with:
  - vtm_add_pool
  - vtm_add_vserver
  - vtm_add_tip

- New action to locate a running vTM when provided with a list of vTMs or
  a Cluster ID.

- Example vADC webhook rule included, and a python script for calling the hook
  from the vTM Alerting framework. Script: `files/st2-trigger.py`
  - New Action to upload webhook: `vadc.vtm_add_webhook_action`

- Added support for vTMs as old as 9.3.
  - Services Director will try universal license and fall back to Legacy FLA

- Added support for list/create/restore/delete backups on vTM 11.0 and above
  - Restore requires Services Director 2.6, if you are proxying

- We now detect the latest version of the API available on the BSD/VTM and use it.

# 0.2.0

- Moved `config.yaml` to `vadc.yaml.example`

# 0.1.0

- First release
