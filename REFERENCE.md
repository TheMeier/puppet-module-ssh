# Reference
<!-- DO NOT EDIT: This document was generated by Puppet Strings -->

## Table of Contents

**Classes**

* [`ssh`](#ssh): install and manage SSH server and client

**Defined types**

* [`ssh::config_entry`](#sshconfig_entry): Create config entries in a users' ~/.ssh/config

**Data types**

* [`Ssh::Log_level`](#sshlog_level): 
* [`Ssh::Permit_root_login`](#sshpermit_root_login): 
* [`Ssh::Syslog_facility`](#sshsyslog_facility): 
* [`Ssh::Yes_no`](#sshyes_no): 

## Classes

### ssh

install and manage SSH server and client

* **Note** default values for paramters are managed with hiera data, see files in the `data` directory.
Paramters marked SSH_CONFIG(5) or SSHD_CONFIG(5) are directly used in the configuration as described
by the corresponding openssh man page

#### Examples

##### Basic usage

```puppet
include ::ssh
```

#### Parameters

The following parameters are available in the `ssh` class.

##### `config_entries`

Data type: `Hash`

parameter for ssh::config_entry factory

Default value: {}

##### `hiera_merge`

Data type: `Boolean`

merge all found instances of ssh::keys and ssh::config_entries in hiera if true

Default value: `false`

##### `keys`

Data type: `Optional[Hash]`

keys for user's ~/.ssh/authorized_keys

Default value: `undef`

##### `manage_firewall`

Data type: `Boolean`

enable/disable firewall rule for ports configured in `$sshd_config_port`

Default value: `false`

##### `manage_root_ssh_config`

Data type: `Boolean`

enable/disable management fo root users ssh_config

Default value: `false`

##### `manage_service`

Data type: `Boolean`

enable/disable management of sshd service

Default value: `true`

##### `packages`

Data type: `Array[String]`

which packages to install

Default value: ['openssh-client', 'openssh-server']

##### `permit_root_login`

Data type: `Ssh::Permit_root_login`

SSHD_CONFIG(5) PermitRootLogin

Default value: 'yes'

##### `purge_keys`

Data type: `Boolean`

enable/disable purging of all unmanaged ssh keys

Default value: `true`

##### `root_ssh_config_content`

Data type: `String`

content of ssh config file for the root user

Default value: "# This file is being maintained by Puppet.\n# DO NOT EDIT\n"

##### `service_enable`

Data type: `Boolean`

enable parameter for sshd service resource

Default value: `true`

##### `service_ensure`

Data type: `String`

ensure parameter for sshd service resource

Default value: 'running'

##### `service_hasrestart`

Data type: `Boolean`

hasrestart parameter for sshd service resource

Default value: `true`

##### `service_hasstatus`

Data type: `Optional[Boolean]`

hasstatus parameter for sshd service resource

Default value: `true`

##### `service_name`

Data type: `String`

name name parameter for sshd service resource

Default value: 'sshd'

##### `ssh_config_ciphers`

Data type: `Optional[Array[String]]`

SSH_CONFIG(5) Ciphers

Default value: `undef`

##### `ssh_config_forward_agent`

Data type: `Optional[String]`

SSH_CONFIG(5) ForwardAgent

Default value: `undef`

##### `ssh_config_forward_x11_trusted`

Data type: `Optional[Enum['yes','no']]`

SSH_CONFIG(5) ForwardX11Trusted

Default value: `undef`

##### `ssh_config_forward_x11`

Data type: `Optional[String]`

SSH_CONFIG(5) ForwardX11

Default value: `undef`

##### `ssh_config_global_known_hosts_file`

Data type: `Stdlib::Absolutepath`

SSH_CONFIG(5) GlobalKnownHostsFile

Default value: '/etc/ssh/ssh_known_hosts'

##### `ssh_config_global_known_hosts_group`

Data type: `String`

group mode for GlobalKnownHostsFile

Default value: 'root'

##### `ssh_config_global_known_hosts_list`

Data type: `Optional[Array[Stdlib::Absolutepath]]`

extra elements to append to GlobalKnownHostsFile

Default value: `undef`

##### `ssh_config_global_known_hosts_mode`

Data type: `Stdlib::Filemode`

file mode for GlobalKnownHostsFile

Default value: '0644'

##### `ssh_config_global_known_hosts_owner`

Data type: `String`

owner for GlobalKnownHostsFile

Default value: 'root'

##### `ssh_config_group`

Data type: `String`

group for ssh config file

Default value: 'root'

##### `ssh_config_hash_known_hosts`

Data type: `Optional[Enum['yes','no']]`

SSH_CONFIG(5) HashKnownHosts

Default value: `undef`

##### `ssh_config_kexalgorithms`

Data type: `Optional[Array[String]]`

SSH_CONFIG(5) KexAlgorithms

Default value: `undef`

##### `ssh_config_macs`

Data type: `Optional[Array[String]]`

SSH_CONFIG(5) MACs

Default value: `undef`

##### `ssh_config_mode`

Data type: `Stdlib::Filemode`

file mode for ssh config file

Default value: '0644'

##### `ssh_config_owner`

Data type: `String`

owner for ssh config file

Default value: 'root'

##### `ssh_config_path`

Data type: `String`

path for ssh config file

Default value: '/etc/ssh/ssh_config'

##### `ssh_config_proxy_command`

Data type: `Optional[String]`

SSH_CONFIG(5) ssh_config_proxy_command

Default value: `undef`

##### `ssh_config_sendenv_xmodifiers`

Data type: `Boolean`

SSH_CONFIG(5) ssh_config_sendenv_xmodifiers

Default value: `false`

##### `ssh_config_server_alive_interval`

Data type: `Optional[String]`

SSH_CONFIG(5) ssh_config_server_alive_interval

Default value: `undef`

##### `ssh_config_template`

Data type: `String`

puppet template to use for ssh config

Default value: 'ssh/ssh_config.erb'

##### `ssh_config_user_known_hosts_file`

Data type: `Optional[Array[String]]`

SSH_CONFIG(5) UserKnownHostsFile

Default value: `undef`

##### `ssh_config_use_roaming`

Data type: `Optional[Enum['yes','no','unset']]`

SSH_CONFIG(5) UseRoaming

Default value: `undef`

##### `sshd_acceptenv`

Data type: `Boolean`

enable/disable AcceptEnv options for specifying environment variables

Default value: `true`

##### `sshd_addressfamily`

Data type: `Optional[Pattern[/^(any|inet|inet6)$/]]`

SSHD_CONFIG(5) sshd_addressfamily

Default value: `undef`

##### `sshd_allow_tcp_forwarding`

Data type: `Enum['yes','no']`

SSHD_CONFIG(5) sshd_allow_tcp_forwarding

Default value: 'yes'

##### `sshd_authorized_keys_command`

Data type: `Optional[Stdlib::Absolutepath]`

SSHD_CONFIG(5) AuthorizedKeysCommand

Default value: `undef`

##### `sshd_authorized_keys_command_user`

Data type: `Optional[String]`

SSHD_CONFIG(5) AuthorizedKeysCommandUser

Default value: `undef`

##### `sshd_banner_content`

Data type: `Optional[String]`

content of ssh banner file

Default value: `undef`

##### `sshd_banner_group`

Data type: `String`

group of ssh banner file

Default value: 'root'

##### `sshd_banner_mode`

Data type: `Stdlib::Filemode`

file mode of ssh banner file

Default value: '0644'

##### `sshd_banner_owner`

Data type: `String`

owner of ssh banner file

Default value: 'root'

##### `sshd_client_alive_count_max`

Data type: `Integer`

SSHD_CONFIG(5) ClientAliveCountMax

Default value: 3

##### `sshd_client_alive_interval`

Data type: `Integer`

SSHD_CONFIG(5) ClientAliveInterval

Default value: 0

##### `sshd_config_allowagentforwarding`

Data type: `Optional[Enum['yes','no']]`

SSHD_CONFIG(5) AllowAgentForwarding

Default value: `undef`

##### `sshd_config_allowgroups`

Data type: `Array[String]`

SSHD_CONFIG(5) AllowGroups

Default value: []

##### `sshd_config_allowusers`

Data type: `Array[String]`

SSHD_CONFIG(5) AllowUsers

Default value: []

##### `sshd_config_authenticationmethods`

Data type: `Optional[Array[String]]`

SSHD_CONFIG(5) AuthenticationMethods

Default value: `undef`

##### `sshd_config_authkey_location`

Data type: `Optional[String]`

SSHD_CONFIG(5) AuthorizedKeysFile

Default value: `undef`

##### `sshd_config_authorized_principals_file`

Data type: `Optional[String]`

SSHD_CONFIG(5) AuthorizedPrincipalsFile

Default value: `undef`

##### `sshd_config_banner`

Data type: `Optional[Stdlib::Absolutepath]`

SSHD_CONFIG(5) Banner

Default value: `undef`

##### `sshd_config_challenge_resp_auth`

Data type: `String`

SSHD_CONFIG(5) ChallengeResponseAuthentication

Default value: 'yes'

##### `sshd_config_chrootdirectory`

Data type: `Optional[Stdlib::Absolutepath]`

SSHD_CONFIG(5) ChrootDirectory

Default value: `undef`

##### `sshd_config_ciphers`

Data type: `Optional[Array[String]]`

SSHD_CONFIG(5) Ciphers

Default value: `undef`

##### `sshd_config_compression`

Data type: `Optional[Enum['yes','no','delayed']]`

SSHD_CONFIG(5) Compression

Default value: `undef`

##### `sshd_config_denygroups`

Data type: `Array[String]`

SSHD_CONFIG(5) DenyGroups

Default value: []

##### `sshd_config_denyusers`

Data type: `Array[String]`

SSHD_CONFIG(5) DenyUsers

Default value: []

##### `sshd_config_forcecommand`

Data type: `Optional[String]`

SSHD_CONFIG(5) DenyGroups

Default value: `undef`

##### `sshd_config_group`

Data type: `String`

group of sshd config file

Default value: 'root'

##### `sshd_config_hostcertificate`

Data type: `Optional[Array[Stdlib::Absolutepath]]`

SSHD_CONFIG(5) HostCertificate

Default value: `undef`

##### `sshd_config_hostkey`

Data type: `Optional[Array[Stdlib::Absolutepath]]`

SSHD_CONFIG(5) HostKey

Default value: ['/etc/ssh/ssh_host_rsa_key']

##### `sshd_config_kexalgorithms`

Data type: `Optional[Array[String]]`

SSHD_CONFIG(5) KexAlgorithms

Default value: `undef`

##### `sshd_config_key_revocation_list`

Data type: `Optional[Stdlib::Absolutepath]`

SSHD_CONFIG(5) RevokedKeys

Default value: `undef`

##### `sshd_config_loglevel`

Data type: `Enum['QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE']`

SSHD_CONFIG(5) LogLevel

Default value: 'INFO'

##### `sshd_config_login_grace_time`

Data type: `String`

SSHD_CONFIG(5) LoginGraceTime

Default value: '120'

##### `sshd_config_macs`

Data type: `Optional[Array[String]]`

SSHD_CONFIG(5) MACs

Default value: `undef`

##### `sshd_config_match`

Data type: `Optional[Hash]`

SSHD_CONFIG(5) Hash for matches with nested arrays for options for the Match
directive for the SSH daemon. Match directive is supported on SSH >= 5.x.

Default value: `undef`

##### `sshd_config_maxauthtries`

Data type: `Optional[Integer]`

SSHD_CONFIG(5) MaxAuthTries

Default value: `undef`

##### `sshd_config_maxsessions`

Data type: `Optional[Integer]`

SSHD_CONFIG(5) MaxSessions

Default value: `undef`

##### `sshd_config_maxstartups`

Data type: `Optional[Pattern[/^((\d+)|(\d+?:\d+?:\d+)?)$/]]`

SSHD_CONFIG(5) MaxStartups

Default value: `undef`

##### `sshd_config_mode`

Data type: `Stdlib::Filemode`

file mode of sshd config file

Default value: '0600'

##### `sshd_config_owner`

Data type: `String`

owner of sshd config file

Default value: 'root'

##### `sshd_config_path`

Data type: `String`

path of sshd config file

Default value: '/etc/ssh/sshd_config'

##### `sshd_config_permitemptypasswords`

Data type: `Optional[Enum['yes','no']]`

SSHD_CONFIG(5) PermitEmptyPasswords

Default value: `undef`

##### `sshd_config_permittunnel`

Data type: `Optional[Enum['yes','no','point-to-point','ethernet']]`

SSHD_CONFIG(5) PermitTunnel

Default value: `undef`

##### `sshd_config_permituserenvironment`

Data type: `Optional[Enum['yes','no']]`

SSHD_CONFIG(5) PermitUserEnvironment

Default value: `undef`

##### `sshd_config_port`

Data type: `Array[Stdlib::Port]`

SSHD_CONFIG(5) Port

Default value: [22]

##### `sshd_config_print_last_log`

Data type: `Optional[Enum['yes','no']]`

SSHD_CONFIG(5) PrintLastLog

Default value: `undef`

##### `sshd_config_print_motd`

Data type: `String`

SSHD_CONFIG(5) PrintMotd

Default value: 'yes'

##### `sshd_config_serverkeybits`

Data type: `Optional[String]`

SSHD_CONFIG(5) ServerKeyBits

Default value: `undef`

##### `sshd_config_strictmodes`

Data type: `Optional[Enum['yes','no']]`

SSHD_CONFIG(5) StrictModes

Default value: `undef`

##### `sshd_config_subsystem_sftp`

Data type: `String`

SSHD_CONFIG(5) Subsystem

Default value: '/usr/lib/openssh/sftp-server'

##### `sshd_config_syslog_facility`

Data type: `String`

SSHD_CONFIG(5) SyslogFacility

Default value: 'AUTH'

##### `sshd_config_tcp_keepalive`

Data type: `Optional[Enum['yes','no']]`

SSHD_CONFIG(5) TCPKeepAlive

Default value: `undef`

##### `sshd_config_template`

Data type: `String`

SSHD_CONFIG(5) puppet template to use for sshd config file

Default value: 'ssh/sshd_config.erb'

##### `sshd_config_trustedusercakeys`

Data type: `Optional[Stdlib::Absolutepath]`

SSHD_CONFIG(5) TrustedUserCAKeys

Default value: `undef`

##### `sshd_config_use_dns`

Data type: `Optional[Enum['yes','no']]`

SSHD_CONFIG(5) UseDNS

Default value: `undef`

##### `sshd_config_use_privilege_separation`

Data type: `Optional[Enum['yes','no','sandbox']]`

SSHD_CONFIG(5) UsePrivilegeSeparation

Default value: `undef`

##### `sshd_config_xauth_location`

Data type: `Optional[Stdlib::Absolutepath]`

SSHD_CONFIG(5) XAuthLocation

Default value: `undef`

##### `sshd_gssapiauthentication`

Data type: `Enum['yes','no']`

SSHD_CONFIG(5) GSSAPIAuthentication

Default value: 'yes'

##### `sshd_gssapicleanupcredentials`

Data type: `Optional[Enum['yes','no']]`

SSHD_CONFIG(5) GSSAPICleanupCredentials

Default value: `undef`

##### `sshd_gssapikeyexchange`

Data type: `Optional[Enum['yes','no']]`

SSHD_CONFIG(5) GSSAPIKeyExchange

Default value: `undef`

##### `sshd_hostbasedauthentication`

Data type: `Enum['yes','no']`

SSHD_CONFIG(5) HostbasedAuthentication

Default value: 'no'

##### `sshd_ignorerhosts`

Data type: `Enum['yes','no']`

SSHD_CONFIG(5) IgnoreRhosts

Default value: 'yes'

##### `sshd_ignoreuserknownhosts`

Data type: `Enum['yes','no']`

SSHD_CONFIG(5) IgnoreUserKnownHosts

Default value: 'no'

##### `sshd_kerberos_authentication`

Data type: `Optional[Enum['yes','no']]`

SSHD_CONFIG(5) KerberosAuthentication

Default value: `undef`

##### `sshd_listen_address`

Data type: `Optional[Array[String]]`

SSHD_CONFIG(5) ListenAddress

Default value: `undef`

##### `sshd_pamauthenticationviakbdint`

Data type: `Optional[Enum['yes','no']]`

SSHD_CONFIG(5) PAMAuthenticationViaKBDInt

Default value: `undef`

##### `sshd_password_authentication`

Data type: `Enum['yes','no']`

SSHD_CONFIG(5) PasswordAuthentication

Default value: 'yes'

##### `sshd_pubkeyacceptedkeytypes`

Data type: `Optional[Array[String]]`

SSHD_CONFIG(5) PubkeyAcceptedKeyTypes

Default value: `undef`

##### `sshd_pubkeyauthentication`

Data type: `Enum['yes','no']`

SSHD_CONFIG(5) PubkeyAuthentication

Default value: 'yes'

##### `sshd_use_pam`

Data type: `Optional[Enum['yes','no']]`

SSHD_CONFIG(5) UsePAM

Default value: `undef`

##### `sshd_x11_forwarding`

Data type: `Enum['yes','no']`

SSHD_CONFIG(5) X11Forwarding

Default value: 'yes'

##### `sshd_x11_use_localhost`

Data type: `Enum['yes','no']`

SSHD_CONFIG(5) X11UseLocalhost

Default value: 'yes'

##### `ssh_enable_ssh_keysign`

Data type: `Optional[Enum['yes','no']]`

SSH_CONFIG(5) EnableSSHKeysign

Default value: `undef`

##### `ssh_gssapiauthentication`

Data type: `Optional[Enum['yes','no']]`

SSH_CONFIG(5) GSSAPIAuthentication

Default value: 'yes'

##### `ssh_gssapidelegatecredentials`

Data type: `Optional[Enum['yes','no']]`

SSH_CONFIG(5) GSSAPIDelegateCredentials

Default value: `undef`

##### `ssh_hostbasedauthentication`

Data type: `Optional[Enum['yes','no']]`

SSH_CONFIG(5) HostbasedAuthentication

Default value: `undef`

##### `ssh_key_ensure`

Data type: `String`

enable/disable to export node sshkey resource

Default value: 'present'

##### `ssh_key_import`

Data type: `Boolean`

enable/disable to import all exported node sshkey resources

Default value: `true`

##### `ssh_key_type`

Data type: `String`

encryption type for SSH key. Valid values are 'ecdsa-sha2-nistp256', 'rsa', 'dsa', 'ssh-dss' and 'ssh-rsa'

Default value: 'ssh-rsa'

##### `ssh_package_adminfile`

Data type: `Optional[Stdlib::Absolutepath]`

adminfile paramter for package resources

Default value: `undef`

##### `ssh_package_source`

Data type: `Optional[Stdlib::Absolutepath]`

source paramter for package resources

Default value: `undef`

##### `ssh_sendenv`

Data type: `Boolean`

enable/disable of SendEnv options for specifying environment variables

Default value: `true`

##### `ssh_strict_host_key_checking`

Data type: `Optional[Enum['yes','no','ask']]`

SSH_CONFIG(5) StrictHostKeyChecking

Default value: `undef`

## Defined types

### ssh::config_entry

@ see https://man.openbsd.org/ssh_config

#### Examples

##### Basic usage

```puppet
ssh::config_entry { 'jenkins github.com':
 host  => 'github.com',
 lines => ["  IdentityFile /home/jenkins/.ssh/jenkins-gihub.key"],
 order => '20',
}
```

#### Parameters

The following parameters are available in the `ssh::config_entry` defined type.

##### `owner`

Data type: `String`



##### `group`

Data type: `String`



##### `path`

Data type: `String`



##### `host`

Data type: `String`



##### `order`

Data type: `Variant[String, Integer]`



Default value: '10'

##### `ensure`

Data type: `String`



Default value: 'present'

##### `lines`

Data type: `Array[String]`



Default value: []

## Data types

### Ssh::Log_level

The Ssh::Log_level data type.

Alias of `Enum['QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE', 'DEBUG', 'DEBUG1', 'DEBUG2', 'DEBUG3']`

### Ssh::Permit_root_login

The Ssh::Permit_root_login data type.

Alias of `Enum['yes', 'prohibit-password', 'without-password', 'forced-commands-only', 'no']`

### Ssh::Syslog_facility

The Ssh::Syslog_facility data type.

Alias of `Enum['DAEMON', 'USER', 'AUTH', 'LOCAL0', 'LOCAL1', 'LOCAL2', 'LOCAL3', 'LOCAL4', 'LOCAL5', 'LOCAL6', 'LOCAL7', 'AUTHPRIV']`

### Ssh::Yes_no

The Ssh::Yes_no data type.

Alias of `Enum['yes', 'no']`

