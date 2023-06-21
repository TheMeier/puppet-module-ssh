# @summary install and manage SSH server and client
#
# @note default values for paramters are managed with hiera data, see files in the `data` directory.
#   Paramters marked SSH_CONFIG(5) or SSHD_CONFIG(5) are directly used in the configuration as described
#   by the corresponding openssh man page
#
# @example Basic usage
#   include ::ssh
#
# @param config_entries parameter for ssh::config_entry factory
# @param hiera_merge merge all found instances of ssh::keys and ssh::config_entries in hiera if true
# @param keys keys for user's ~/.ssh/authorized_keys
# @param manage_firewall enable/disable firewall rule for ports configured in `$sshd_config_port`
# @param manage_root_ssh_config enable/disable management fo root users ssh_config
# @param manage_service enable/disable management of sshd service
# @param packages which packages to install
# @param permit_root_login SSHD_CONFIG(5) PermitRootLogin
# @param purge_keys enable/disable purging of all unmanaged ssh keys
# @param root_ssh_config_content content of ssh config file for the root user
# @param service_enable enable parameter for sshd service resource
# @param service_ensure ensure parameter for sshd service resource
# @param service_hasrestart hasrestart parameter for sshd service resource
# @param service_hasstatus hasstatus parameter for sshd service resource
# @param service_name name name parameter for sshd service resource
# @param ssh_config_ciphers SSH_CONFIG(5) Ciphers
# @param ssh_config_forward_agent SSH_CONFIG(5) ForwardAgent
# @param ssh_config_forward_x11_trusted SSH_CONFIG(5) ForwardX11Trusted
# @param ssh_config_forward_x11 SSH_CONFIG(5) ForwardX11
# @param ssh_config_global_known_hosts_file SSH_CONFIG(5) GlobalKnownHostsFile
# @param ssh_config_global_known_hosts_group group mode for GlobalKnownHostsFile
# @param ssh_config_global_known_hosts_list extra elements to append to GlobalKnownHostsFile
# @param ssh_config_global_known_hosts_mode file mode for GlobalKnownHostsFile
# @param ssh_config_global_known_hosts_owner owner for GlobalKnownHostsFile
# @param ssh_config_group group for ssh config file
# @param ssh_config_hash_known_hosts SSH_CONFIG(5) HashKnownHosts
# @param ssh_config_kexalgorithms SSH_CONFIG(5) KexAlgorithms
# @param ssh_config_macs SSH_CONFIG(5) MACs
# @param ssh_config_mode file mode for ssh config file
# @param ssh_config_owner owner for ssh config file
# @param ssh_config_path path for ssh config file
# @param ssh_config_proxy_command SSH_CONFIG(5) ssh_config_proxy_command
# @param ssh_config_sendenv_xmodifiers SSH_CONFIG(5) ssh_config_sendenv_xmodifiers
# @param ssh_config_server_alive_interval SSH_CONFIG(5) ssh_config_server_alive_interval
# @param ssh_config_template puppet template to use for ssh config
# @param ssh_config_user_known_hosts_file SSH_CONFIG(5) UserKnownHostsFile
# @param ssh_config_use_roaming SSH_CONFIG(5) UseRoaming
# @param sshd_acceptenv enable/disable AcceptEnv options for specifying environment variables
# @param sshd_addressfamily SSHD_CONFIG(5) sshd_addressfamily
# @param sshd_allow_tcp_forwarding SSHD_CONFIG(5) sshd_allow_tcp_forwarding
# @param sshd_authorized_keys_command SSHD_CONFIG(5) AuthorizedKeysCommand
# @param sshd_authorized_keys_command_user SSHD_CONFIG(5) AuthorizedKeysCommandUser
# @param sshd_banner_content content of ssh banner file
# @param sshd_banner_group group of ssh banner file
# @param sshd_banner_mode file mode of ssh banner file
# @param sshd_banner_owner owner of ssh banner file
# @param sshd_client_alive_count_max SSHD_CONFIG(5) ClientAliveCountMax
# @param sshd_client_alive_interval SSHD_CONFIG(5) ClientAliveInterval
# @param sshd_config_allowagentforwarding SSHD_CONFIG(5) AllowAgentForwarding
# @param sshd_config_allowgroups SSHD_CONFIG(5) AllowGroups
# @param sshd_config_allowusers SSHD_CONFIG(5) AllowUsers
# @param sshd_config_authenticationmethods SSHD_CONFIG(5) AuthenticationMethods
# @param sshd_config_authkey_location SSHD_CONFIG(5) AuthorizedKeysFile
# @param sshd_config_authorized_principals_file SSHD_CONFIG(5) AuthorizedPrincipalsFile
# @param sshd_config_banner SSHD_CONFIG(5) Banner
# @param sshd_config_challenge_resp_auth SSHD_CONFIG(5) ChallengeResponseAuthentication
# @param sshd_config_chrootdirectory SSHD_CONFIG(5) ChrootDirectory
# @param sshd_config_ciphers SSHD_CONFIG(5) Ciphers
# @param sshd_config_compression SSHD_CONFIG(5) Compression
# @param sshd_config_denygroups SSHD_CONFIG(5) DenyGroups
# @param sshd_config_denyusers SSHD_CONFIG(5) DenyUsers
# @param sshd_config_forcecommand SSHD_CONFIG(5) DenyGroups
# @param sshd_config_group group of sshd config file
# @param sshd_config_hostcertificate SSHD_CONFIG(5) HostCertificate
# @param sshd_config_hostkey SSHD_CONFIG(5) HostKey
# @param sshd_config_kexalgorithms SSHD_CONFIG(5) KexAlgorithms
# @param sshd_config_key_revocation_list SSHD_CONFIG(5) RevokedKeys
# @param sshd_config_loglevel SSHD_CONFIG(5) LogLevel
# @param sshd_config_login_grace_time SSHD_CONFIG(5) LoginGraceTime
# @param sshd_config_macs SSHD_CONFIG(5) MACs
# @param sshd_config_match SSHD_CONFIG(5) Hash for matches with nested arrays for options for the Match
#   directive for the SSH daemon. Match directive is supported on SSH >= 5.x.
# @param sshd_config_maxauthtries SSHD_CONFIG(5) MaxAuthTries
# @param sshd_config_maxsessions SSHD_CONFIG(5) MaxSessions
# @param sshd_config_maxstartups SSHD_CONFIG(5) MaxStartups
# @param sshd_config_mode file mode of sshd config file
# @param sshd_config_owner owner of sshd config file
# @param sshd_config_path path of sshd config file
# @param sshd_config_permitemptypasswords SSHD_CONFIG(5) PermitEmptyPasswords
# @param sshd_config_permittunnel SSHD_CONFIG(5) PermitTunnel
# @param sshd_config_permituserenvironment SSHD_CONFIG(5) PermitUserEnvironment
# @param sshd_config_port SSHD_CONFIG(5) Port
# @param sshd_config_print_last_log SSHD_CONFIG(5) PrintLastLog
# @param sshd_config_print_motd SSHD_CONFIG(5) PrintMotd
# @param sshd_config_serverkeybits SSHD_CONFIG(5) ServerKeyBits
# @param sshd_config_strictmodes SSHD_CONFIG(5) StrictModes
# @param sshd_config_subsystem_sftp SSHD_CONFIG(5) Subsystem
# @param sshd_config_syslog_facility SSHD_CONFIG(5) SyslogFacility
# @param sshd_config_tcp_keepalive SSHD_CONFIG(5) TCPKeepAlive
# @param sshd_config_template SSHD_CONFIG(5) puppet template to use for sshd config file
# @param sshd_config_trustedusercakeys SSHD_CONFIG(5) TrustedUserCAKeys
# @param sshd_config_use_dns SSHD_CONFIG(5) UseDNS
# @param sshd_config_use_privilege_separation SSHD_CONFIG(5) UsePrivilegeSeparation
# @param sshd_config_xauth_location SSHD_CONFIG(5) XAuthLocation
# @param sshd_gssapiauthentication SSHD_CONFIG(5) GSSAPIAuthentication
# @param sshd_gssapicleanupcredentials SSHD_CONFIG(5) GSSAPICleanupCredentials
# @param sshd_gssapikeyexchange SSHD_CONFIG(5) GSSAPIKeyExchange
# @param sshd_hostbasedauthentication SSHD_CONFIG(5) HostbasedAuthentication
# @param sshd_ignorerhosts SSHD_CONFIG(5) IgnoreRhosts
# @param sshd_ignoreuserknownhosts SSHD_CONFIG(5) IgnoreUserKnownHosts
# @param sshd_kerberos_authentication SSHD_CONFIG(5) KerberosAuthentication
# @param sshd_listen_address SSHD_CONFIG(5) ListenAddress
# @param sshd_pamauthenticationviakbdint SSHD_CONFIG(5) PAMAuthenticationViaKBDInt
# @param sshd_password_authentication SSHD_CONFIG(5) PasswordAuthentication
# @param sshd_pubkeyacceptedkeytypes SSHD_CONFIG(5) PubkeyAcceptedKeyTypes
# @param sshd_pubkeyauthentication SSHD_CONFIG(5) PubkeyAuthentication
# @param sshd_use_pam SSHD_CONFIG(5) UsePAM
# @param sshd_x11_forwarding SSHD_CONFIG(5) X11Forwarding
# @param sshd_x11_use_localhost SSHD_CONFIG(5) X11UseLocalhost
# @param ssh_enable_ssh_keysign SSH_CONFIG(5) EnableSSHKeysign
# @param ssh_gssapiauthentication SSH_CONFIG(5) GSSAPIAuthentication
# @param ssh_gssapidelegatecredentials SSH_CONFIG(5) GSSAPIDelegateCredentials
# @param ssh_hostbasedauthentication SSH_CONFIG(5) HostbasedAuthentication
# @param ssh_key_ensure enable/disable to export node sshkey resource
# @param ssh_key_import enable/disable to import all exported node sshkey resources
# @param ssh_key_type encryption type for SSH key.
# @param ssh_package_adminfile adminfile paramter for package resources
# @param ssh_package_source source paramter for package resources
# @param ssh_sendenv enable/disable of SendEnv options for specifying environment variables
# @param ssh_strict_host_key_checking SSH_CONFIG(5) StrictHostKeyChecking
class ssh (
  Hash $config_entries = {},
  Boolean $hiera_merge = false,
  Optional[Hash] $keys = undef,
  Boolean $manage_firewall = false,
  Boolean $manage_root_ssh_config = false,
  Boolean $manage_service = true,
  Array[String] $packages = ['openssh-client', 'openssh-server'],
  Ssh::Permit_root_login $permit_root_login = 'yes',
  Boolean $purge_keys = true,
  String $root_ssh_config_content = "# This file is being maintained by Puppet.\n# DO NOT EDIT\n",
  Boolean $service_enable = true,
  String $service_ensure = 'running',
  Boolean $service_hasrestart = true,
  Boolean $service_hasstatus = true,
  String $service_name = 'sshd',
  Optional[Array[String]] $ssh_config_ciphers = undef,
  Optional[String] $ssh_config_forward_agent = undef,
  Optional[Enum['yes','no']] $ssh_config_forward_x11_trusted = undef,
  Optional[String] $ssh_config_forward_x11 = undef,
  Stdlib::Absolutepath $ssh_config_global_known_hosts_file = '/etc/ssh/ssh_known_hosts',
  String $ssh_config_global_known_hosts_group = 'root',
  Optional[Array[Stdlib::Absolutepath]] $ssh_config_global_known_hosts_list = undef,
  Stdlib::Filemode $ssh_config_global_known_hosts_mode = '0644',
  String $ssh_config_global_known_hosts_owner = 'root',
  String $ssh_config_group = 'root',
  Optional[Enum['yes','no']] $ssh_config_hash_known_hosts = undef,
  Optional[Array[String]] $ssh_config_kexalgorithms = undef,
  Optional[Array[String]] $ssh_config_macs = undef,
  Stdlib::Filemode $ssh_config_mode = '0644',
  String $ssh_config_owner = 'root',
  String $ssh_config_path = '/etc/ssh/ssh_config',
  Optional[String] $ssh_config_proxy_command = undef,
  Boolean $ssh_config_sendenv_xmodifiers = false,
  Optional[String] $ssh_config_server_alive_interval = undef,
  String $ssh_config_template = 'ssh/ssh_config.erb',
  Optional[Array[String]] $ssh_config_user_known_hosts_file = undef,
  Optional[Enum['yes','no','unset']] $ssh_config_use_roaming = undef,
  Boolean $sshd_acceptenv = true,
  Optional[Pattern[/^(any|inet|inet6)$/]] $sshd_addressfamily = undef,
  Enum['yes','no'] $sshd_allow_tcp_forwarding = 'yes',
  Optional[Stdlib::Absolutepath] $sshd_authorized_keys_command = undef,
  Optional[String] $sshd_authorized_keys_command_user = undef,
  Optional[String] $sshd_banner_content = undef,
  String $sshd_banner_group = 'root',
  Stdlib::Filemode $sshd_banner_mode = '0644',
  String $sshd_banner_owner = 'root',
  Integer $sshd_client_alive_count_max = 3,
  Integer $sshd_client_alive_interval = 0,
  Optional[Enum['yes','no']] $sshd_config_allowagentforwarding = undef,
  Array[String] $sshd_config_allowgroups = [],
  Array[String] $sshd_config_allowusers = [],
  Optional[Array[String]] $sshd_config_authenticationmethods = undef,
  Optional[String] $sshd_config_authkey_location = undef,
  Optional[String] $sshd_config_authorized_principals_file = undef,
  Optional[Stdlib::Absolutepath] $sshd_config_banner = undef,
  String $sshd_config_challenge_resp_auth = 'yes',
  Optional[Stdlib::Absolutepath] $sshd_config_chrootdirectory = undef,
  Optional[Array[String]] $sshd_config_ciphers = undef,
  Optional[Enum['yes','no','delayed']] $sshd_config_compression = undef,
  Array[String] $sshd_config_denygroups = [],
  Array[String] $sshd_config_denyusers = [],
  Optional[String] $sshd_config_forcecommand = undef,
  String $sshd_config_group = 'root',
  Optional[Array[Stdlib::Absolutepath]] $sshd_config_hostcertificate = undef,
  Array[Stdlib::Absolutepath] $sshd_config_hostkey = ['/etc/ssh/ssh_host_rsa_key'],
  Optional[Array[String]] $sshd_config_kexalgorithms = undef,
  Optional[Stdlib::Absolutepath] $sshd_config_key_revocation_list = undef,
  Enum['QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE'] $sshd_config_loglevel = 'INFO',
  String $sshd_config_login_grace_time = '120',
  Optional[Array[String]] $sshd_config_macs = undef,
  Optional[Hash] $sshd_config_match = undef,
  Optional[Integer] $sshd_config_maxauthtries = undef,
  Optional[Integer] $sshd_config_maxsessions = undef,
  Optional[Pattern[/^((\d+)|(\d+?:\d+?:\d+)?)$/]] $sshd_config_maxstartups = undef,
  Stdlib::Filemode $sshd_config_mode = '0600',
  String $sshd_config_owner = 'root',
  String $sshd_config_path = '/etc/ssh/sshd_config',
  Optional[Enum['yes','no']] $sshd_config_permitemptypasswords = undef,
  Optional[Enum['yes','no','point-to-point','ethernet']] $sshd_config_permittunnel = undef,
  Optional[Enum['yes','no']] $sshd_config_permituserenvironment = undef,
  Array[Stdlib::Port] $sshd_config_port = [22],
  Optional[Enum['yes','no']] $sshd_config_print_last_log = undef,
  String $sshd_config_print_motd = 'yes',
  Optional[String] $sshd_config_serverkeybits = undef,
  Optional[Enum['yes','no']] $sshd_config_strictmodes = undef,
  String $sshd_config_subsystem_sftp = '/usr/lib/openssh/sftp-server',
  String $sshd_config_syslog_facility = 'AUTH',
  Optional[Enum['yes','no']] $sshd_config_tcp_keepalive              = undef,
  String $sshd_config_template = 'ssh/sshd_config.erb',
  Optional[Stdlib::Absolutepath] $sshd_config_trustedusercakeys = undef,
  Optional[Enum['yes','no']] $sshd_config_use_dns = undef,
  Optional[Enum['yes','no','sandbox']] $sshd_config_use_privilege_separation   = undef,
  Optional[Stdlib::Absolutepath] $sshd_config_xauth_location = undef,
  Enum['yes','no'] $sshd_gssapiauthentication = 'yes',
  Optional[Enum['yes','no']] $sshd_gssapicleanupcredentials = undef,
  Optional[Enum['yes','no']] $sshd_gssapikeyexchange = undef,
  Enum['yes','no'] $sshd_hostbasedauthentication = 'no',
  Enum['yes','no'] $sshd_ignorerhosts = 'yes',
  Enum['yes','no'] $sshd_ignoreuserknownhosts = 'no',
  Optional[Enum['yes','no']] $sshd_kerberos_authentication = undef,
  Optional[Array[String]] $sshd_listen_address = undef,
  Optional[Enum['yes','no']] $sshd_pamauthenticationviakbdint = undef,
  Enum['yes','no'] $sshd_password_authentication = 'yes',
  Optional[Array[String]] $sshd_pubkeyacceptedkeytypes = undef,
  Enum['yes','no'] $sshd_pubkeyauthentication = 'yes',
  Optional[Enum['yes','no']] $sshd_use_pam = undef,
  Enum['yes','no'] $sshd_x11_forwarding = 'yes',
  Enum['yes','no'] $sshd_x11_use_localhost = 'yes',
  Optional[Enum['yes','no']] $ssh_enable_ssh_keysign = undef,
  Enum['yes','no'] $ssh_gssapiauthentication = 'yes',
  Optional[Enum['yes','no']] $ssh_gssapidelegatecredentials = undef,
  Optional[Enum['yes','no']] $ssh_hostbasedauthentication = undef,
  String $ssh_key_ensure = 'present',
  Boolean $ssh_key_import = true,
  SSH::Key_type $ssh_key_type = 'ssh-rsa',
  Optional[Stdlib::Absolutepath] $ssh_package_adminfile = undef,
  Optional[Stdlib::Absolutepath] $ssh_package_source = undef,
  Boolean $ssh_sendenv = true,
  Optional[Enum['yes','no','ask']] $ssh_strict_host_key_checking = undef,
) {
  if "${facts['ssh_version']}" =~ /^OpenSSH/ { # lint:ignore:only_variable_string
    $ssh_version_array = split($facts['ssh_version_numeric'], '\.')
    $ssh_version_maj_int = Integer($ssh_version_array[0])
    $ssh_version_min_int = Integer($ssh_version_array[1])
    if $ssh_version_maj_int > 5 {
      $default_ssh_config_use_roaming = 'no'
    } elsif $ssh_version_maj_int == 5 and $ssh_version_min_int >= 4 {
      $default_ssh_config_use_roaming = 'no'
    } else {
      $default_ssh_config_use_roaming = 'unset'
    }
  } else {
    $default_ssh_config_use_roaming = 'unset'
  }

  if $ssh_config_use_roaming == undef {
    $ssh_config_use_roaming_real = $default_ssh_config_use_roaming
  } else {
    $ssh_config_use_roaming_real = $ssh_config_use_roaming
  }

  case $sshd_config_maxsessions {
    undef:   { $sshd_config_maxsessions_integer = undef }
    default: { $sshd_config_maxsessions_integer = floor($sshd_config_maxsessions) }
  }

  case $sshd_config_hostcertificate {
    'unset', undef: { $sshd_config_hostcertificate_real = undef }
    default:        { $sshd_config_hostcertificate_real = $sshd_config_hostcertificate }
  }

  if $sshd_banner_content != undef and $sshd_config_banner == undef {
    fail('ssh::sshd_config_banner must be set to be able to use sshd_banner_content.')
  }

  case $ssh_key_type {
    'ssh-rsa','rsa': {
      $key = $facts['ssh']['rsa']['key']
    }
    'ssh-dsa','dsa': {
      $key = $facts['ssh']['dsa']['key']
    }
    'ecdsa-sha2-nistp256': {
      $key = $facts['ssh']['ecdsa']['key']
    }
    'ssh-ed25519': {
      $key = $facts['ssh']['ed25519']['key']
    }
    default: {
      fail('ssh::ssh_key_type is invalid')
    }
  }

  $ssh_config_global_known_hosts_file_real = any2array($ssh_config_global_known_hosts_file)

  if $ssh_config_global_known_hosts_list != undef {
    $ssh_config_global_known_hosts_list_real = concat($ssh_config_global_known_hosts_file_real, $ssh_config_global_known_hosts_list)
  } else {
    $ssh_config_global_known_hosts_list_real = $ssh_config_global_known_hosts_file_real
  }

  $supported_loglevel_vals= ['QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE']

  #enable hiera merging for groups, users, and config_entries
  if $hiera_merge == true {
    $sshd_config_allowgroups_real = hiera_array('ssh::sshd_config_allowgroups', [])
    $sshd_config_allowusers_real  = hiera_array('ssh::sshd_config_allowusers', [])
    $sshd_config_denygroups_real  = hiera_array('ssh::sshd_config_denygroups', [])
    $sshd_config_denyusers_real   = hiera_array('ssh::sshd_config_denyusers', [])
    $config_entries_real          = hiera_hash('ssh::config_entries', {})
  } else {
    $sshd_config_allowgroups_real = $sshd_config_allowgroups
    $sshd_config_allowusers_real  = $sshd_config_allowusers
    $sshd_config_denygroups_real  = $sshd_config_denygroups
    $sshd_config_denyusers_real   = $sshd_config_denyusers
    $config_entries_real          = $config_entries
  }

  package { $packages:
    ensure    => installed,
    source    => $ssh_package_source,
    adminfile => $ssh_package_adminfile,
  }

  file { 'ssh_config' :
    ensure  => file,
    path    => $ssh_config_path,
    owner   => $ssh_config_owner,
    group   => $ssh_config_group,
    mode    => $ssh_config_mode,
    content => template($ssh_config_template),
    require => Package[$packages],
  }

  file { 'sshd_config' :
    ensure  => file,
    path    => $sshd_config_path,
    mode    => $sshd_config_mode,
    owner   => $sshd_config_owner,
    group   => $sshd_config_group,
    content => template($sshd_config_template),
    require => Package[$packages],
  }

  if $sshd_config_banner != undef and $sshd_banner_content != undef {
    file { 'sshd_banner' :
      ensure  => file,
      path    => $sshd_config_banner,
      owner   => $sshd_banner_owner,
      group   => $sshd_banner_group,
      mode    => $sshd_banner_mode,
      content => $sshd_banner_content,
      require => Package[$packages],
    }
  }

  if $manage_root_ssh_config == true {
    file { 'root_ssh_dir':
      ensure => directory,
      path   => "${facts['root_home']}/.ssh",
      owner  => 'root',
      group  => 'root',
      mode   => '0700',
    }

    file { 'root_ssh_config':
      ensure  => file,
      path    => "${facts['root_home']}/.ssh/config",
      content => $root_ssh_config_content,
      owner   => 'root',
      group   => 'root',
      mode    => '0600',
    }
  }

  if $manage_service {
    service { 'sshd_service' :
      ensure     => $service_ensure,
      name       => $service_name,
      enable     => $service_enable,
      hasrestart => $service_hasrestart,
      hasstatus  => $service_hasstatus,
      subscribe  => File['sshd_config'],
    }
  }

  if $manage_firewall == true {
    $sshd_config_port.each |$_port| {
      firewall { "${_port} open port ${_port} for SSH":
        action => 'accept',
        dport  => $_port,
        proto  => 'tcp',
      }
    }
  }

  # If either IPv4 or IPv6 stack is not configured on the agent, the
  # corresponding $::ipaddress(6)? fact is not present. So, we cannot assume
  # these variables are defined. Getvar (Stdlib 4.13+, ruby 1.8.7+) handles
  # this correctly.
  if getvar('::ipaddress') and getvar('::ipaddress6') {
    $host_aliases = [
      $facts['networking']['hostname'],
      $facts['networking']['ip'],
      $facts['networking']['ip6'],
    ]
  }
  elsif getvar('::ipaddress6') {
    $host_aliases = [
      $facts['networking']['hostname'],
      $facts['networking']['ip6'],
    ]
  }
  else {
    $host_aliases = [
      $facts['networking']['hostname'],
      $facts['networking']['ip'],
    ]
  }

  # export each node's ssh key
  @@sshkey { $facts['networking']['fqdn'] :
    ensure       => $ssh_key_ensure,
    host_aliases => $host_aliases,
    type         => $ssh_key_type,
    key          => $key,
  }

  file { 'ssh_known_hosts':
    ensure  => file,
    path    => $ssh_config_global_known_hosts_file,
    owner   => $ssh_config_global_known_hosts_owner,
    group   => $ssh_config_global_known_hosts_group,
    mode    => $ssh_config_global_known_hosts_mode,
    require => Package[$packages],
  }

  # import all nodes' ssh keys
  if $ssh_key_import {
    Sshkey <<||>> {
      target => $ssh_config_global_known_hosts_file,
    }
  }

  # remove ssh key's not managed by puppet
  resources { 'sshkey':
    purge => $purge_keys,
  }

  # manage users' ssh config entries if present
  create_resources('ssh::config_entry',$config_entries_real)

  # manage users' ssh authorized keys if present
  if $keys != undef {
    if $hiera_merge == true {
      $keys_real = hiera_hash('ssh::keys')
    } else {
      $keys_real = $keys
      notice('Future versions of the ssh module will default ssh::hiera_merge to true')
    }
    create_resources('ssh_authorized_key', $keys_real)
  }

  if $sshd_addressfamily != undef {
    if $facts['os']['family'] == 'Solaris' {
      fail("ssh::sshd_addressfamily is not supported on Solaris and is set to <${sshd_addressfamily}>.")
    }
  }
}
