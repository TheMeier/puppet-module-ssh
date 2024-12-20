# Change log

## [v5.0.0](https://github.com/TheMeier/puppet-module-ssh/tree/v5.0.0) (2023-06-21)
[Full Changelog](https://github.com/TheMeier/puppet-module-ssh/compare/v4.0.2...v5.0.0)

### Changed
- update pdk templates
- Allow ssh-ed25519 hostkeys

## Breaking changes
- drop puppet 6 support
- drop all OS support except for Debian

## [v4.0.2](https://github.com/TheMeier/puppet-module-ssh/tree/v4.0.2) (2020-06-02)

[Full Changelog](https://github.com/TheMeier/puppet-module-ssh/compare/v4.0.1...v4.0.2)

### Changed

- update pdk templates
- add empty hash to `data/common.yaml` (PDK-1633)
- drop puppet 5 support
- use litmusimage in acceptance test

## [v4.0.1](https://github.com/TheMeier/puppet-module-ssh/tree/v4.0.1) (2019-09-13)

[Full Changelog](https://github.com/TheMeier/puppet-module-ssh/compare/v4.0.0...v4.0.1)

### Changed

- Use type aliases for some paramters
- Reformat changelog
- generate firewall rules for all port in `$sshd_config_port` instead of fixed port 22
- add REFERENCE.md
- use puppet strings for documentation
- add basic acceptance test

## v4.0.0 - 2019-10-13

- convert to use pdk
- use types
- update list of supported OSes
- BREAKING: manage_root_ssh_config doe not accept strings anymore
- BREAKING: sshd_config_port requires an array of Stdlib::Port now
- BREAKING: sshd_config_hostcertificate requires an array of Stdlib::Absolutepath now
- BREAKING: ssh_config_sendenv_xmodifiers must be a Boolean now
- BREAKING: hiera_merge must be a Boolean now
- BREAKING: ssh_config_hash_known_hosts,sshd_config_authorized_principals_file,sshd_config_permittunnel and sshd_config_tcp_keepalive do not support 'unset' anymore
- BREAKING: sshd_config_trustedusercakeys and sshd_config_key_revocation_list does not support 'unset' and 'none' anymore

## v3.62.0 - 2019-09-17

- Support Debian 10

## v3.61.0 - 2019-05-01

- Support Debian 8
- Support Ubuntu 18.04 LTS

## v3.60.1 - 2019-04-29

- Fix screwed up metadata

## v3.60.0 - 2019-04-29

- Support Debian 9
- Add ability for IPv6 addresses to be exported as part of the sshkey
      for the FQDN.

## v3.59.1 - 2019-02-28

- Put Match block at end of sshd_config

## v3.59.0 - 2018-01-03

- Support Puppet 6

## v3.58.0 - 2018-10-08

- Add RevokedKeys option to `sshd_config`

## v3.57.1 - 2018-07-27

- Disable ServerkeyBits on RHEL 7.4 and later

## v3.57.0 - 2017-12-10

- Add support for AuthenticationMethods and AllowAgentForwarding
    options in sshd_config

## v3.56.1 - 2017-11-20

- Fix regex bug with `sshd_config_maxstartups`

## v3.56.0 - 2017-10-27

- Support puppetlabs/concat v3 and v4

## v3.55.0 - 2017-09-26

- Add `ssh::config_entry` defined type to manage `~/.ssh/config`
- Add `config_entries` parameter to ssh class to allow specifying a
    hash of multiple entries for `ssh::config_entry`.

## v3.54.0 - 2017-07-24

- Allow sshd_config_hostcertificate to be an array. This fixes a bug
    where you could have specified one cert and multiple HostKey's since
    `sshd_config_hostkey` allows an array.
- Add parameter `sshd_config_authorized_principals_file` to manage the
    `AuthorizedPrincipalsFile` setting in `sshd_config`.

## v3.53.0 - 2017-07-24

- Support only latest Puppet v3
- Support only last few releases on Puppet v4
- Add support for Puppet v5

## v3.52.0 - 2017-05-26

- Add params for Add PrintLastLog, UsePrivilegeSeparation, and
    Compression options in sshd_config.

## v3.51.1 - 2017-05-19

- Ensure that ssh_known_hosts requires the ssh packages

## v3.51.0 - 2017-05-17

- Add params sshd_config_hostcertificate and
    sshd_config_trustedusercakeys to set HostCertificate and TrustedUserCAKeys.

## v3.50.0 - 2017-05-08

- Add param sshd_pubkeyacceptedkeytypes to set PubkeyAcceptedKeyTypes

## v3.49.1 - 2017-02-27

- Fix parameters not compatible with Solaris
- Add support for Puppet v4.9

## v3.49.0 - 2016-10-25

- Add support for PermitTunnel in sshd_config

## v3.48.0 - 2016-10-20

- Add support for ProxyCommand

## v3.47.0 - 2016-10-19

- Add support for KexAlgorithms

## v3.46.0 - 2016-10-04

- Add sshd_x11_use_localhost parameter

## v3.45.0 - 2016-08-30

- Add support for Ubuntu 16.04 LTS

## v3.44.0 - 2016-08-28

- Add support for TCPKeepAlive in sshd_config

## v3.43.0 - 2016-08-08

- Add support for Ruby 2.3.1 with Puppet v4

## v3.42.0 - 2016-06-24

- Add support for managing sshd_config options PermitUserEnvironment and
    PermitEmptyPasswords

## v3.41.1 - 2016-06-20

- Update years in LICENSE

## v3.41.0 - 2016-06-20

- Add ability to specify an array for GlobalKnownHostsFile in ssh_config.
- Add support for UserKnownHostsFile in ssh_config.

## v3.40.0 - 2016-06-09

- Add ability to specify multiple ports

## v3.39.0 - 2016-06-08

- Allow ecdsa-sha2-nistp256 hostkeys
- Add host_aliases attribute to sshkey resource
- Add support for PubkeyAuthentication in sshd_config

## v3.38.0 - 2016-06-06

- Add param to manage MaxAuthTries in sshd_config

## v2.0.0 - 2013-05-16 Garrett Honeycutt <code@garretthoneycutt.com>

- Rebirth
