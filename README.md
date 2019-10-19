# puppet-module-ssh

Manage ssh client and server.

The module uses exported resources to manage ssh keys and removes ssh keys that
are not managed by puppet. This behavior is managed by the parameters
ssh_key_ensure and purge_keys.

This module may be used with a simple `include ::ssh`

The `ssh::config_entry` defined type may be used directly and is used to manage
Host entries in a personal `~/.ssh/config` file.

See also [REFERENCE.md](REFERENCE.md)

## Compatibility

This module has been tested to work on the following systems with the
Puppet v5 and v6. See [metadata.json](metadata.json) for the exact matrix of supported Puppet and OS versions.

If you use the Sun Solaris SSH, please keep in mind that not all parameters can be used.

Unsupported parameters for ssh_config:
AddressFamily, Tunnel, TunnelDevice, PermitLocalCommand, HashKnownHosts

Unsupported parameters for sshd_config:
KerberosOrLocalPasswd, KerberosTicketCleanup, KerberosGetAFSToken, TCPKeepAlive, ShowPatchLevel, MaxSessions, PermitTunnel

## Manage user's ssh_authorized_keys

This works by passing the ssh::keys hash to the ssh_authorized_keys type with create_resources(). Because of this, you may specify any valid parameter for ssh_authorized_key. See the [Type Reference](https://github.com/puppetlabs/puppetlabs-sshkeys_core/blob/master/REFERENCE.md#ssh_authorized_key) for a complete list.

### Sample usage

Push authorized key "root_for_userX" and remove key "root_for_userY" through Hiera.

```yaml
ssh::keys:
  root_for_userX:
    ensure: present
    user: root
    type: dsa
    key: AAAA...==
  apachehup:
    ensure: present
    user: apachehup
    type: rsa
    key: 'AAAA...=='
    options: 'command="/sbin/service httpd restart"'
  root_for_userY:
    ensure: absent
    user: root
```

Manage config entries in a personal ssh/config file.

```puppet
Ssh::Config_entry {
  ensure => present,
  path   => '/home/jenkins/.ssh/config',
  owner  => 'jenkins',
  group  => 'jenkins',
}


ssh::config_entry { 'jenkins *':
  host  => '*',
  lines => [
    '  ForwardX11 no',
    '  StrictHostKeyChecking no',
  ],
  order => '10',
}

ssh::config_entry { 'jenkins github.com':
  host  => 'github.com',
  lines => ["  IdentityFile /home/jenkins/.ssh/jenkins-gihub.key"],
  order => '20',
}
```
