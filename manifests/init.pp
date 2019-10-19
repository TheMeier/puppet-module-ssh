# == Class: ssh
#
# Manage ssh client and server
#
class ssh (
  Boolean $hiera_merge = false,
  Array[String] $packages = ['openssh-client', 'openssh-server'],
  Ssh::Permit_root_login $permit_root_login = 'yes',
  Boolean $purge_keys = true,
  Boolean $manage_firewall = false,
  Optional[Stdlib::Absolutepath] $ssh_package_source = undef,
  Optional[Stdlib::Absolutepath] $ssh_package_adminfile = undef,
  Optional[Ssh::Yes_no] $ssh_config_hash_known_hosts = undef,
  String $ssh_config_path = '/etc/ssh/ssh_config',
  String $ssh_config_owner = 'root',
  String $ssh_config_group = 'root',
  Stdlib::Filemode $ssh_config_mode = '0644',
  Optional[String] $ssh_config_forward_x11 = undef,
  Optional[Ssh::Yes_no] $ssh_config_forward_x11_trusted = undef,
  Optional[String] $ssh_config_forward_agent = undef,
  Optional[String] $ssh_config_server_alive_interval = undef,
  Boolean $ssh_config_sendenv_xmodifiers = false,
  Optional[Ssh::Yes_no] $ssh_hostbasedauthentication = undef,
  Optional[String] $ssh_config_proxy_command = undef,
  Optional[Enum['yes','no','ask']] $ssh_strict_host_key_checking = undef,
  Optional[Array[String]] $ssh_config_ciphers = undef,
  Optional[Array[String]] $ssh_config_kexalgorithms = undef,
  Optional[Array[String]] $ssh_config_macs = undef,
  Optional[Enum['yes','no','unset']] $ssh_config_use_roaming = undef,
  String $ssh_config_template = 'ssh/ssh_config.erb',
  Boolean $ssh_sendenv = true,
  Optional[Ssh::Yes_no] $ssh_gssapiauthentication = 'yes',
  Optional[Ssh::Yes_no] $ssh_gssapidelegatecredentials = undef,
  String $sshd_config_path = '/etc/ssh/sshd_config',
  String $sshd_config_owner = 'root',
  String $sshd_config_group = 'root',
  Ssh::Log_level $sshd_config_loglevel = 'INFO',
  Stdlib::Filemode $sshd_config_mode = '0600',
  Optional[Ssh::Yes_no] $sshd_config_permitemptypasswords = undef,
  Optional[Ssh::Yes_no] $sshd_config_permituserenvironment = undef,
  Optional[Enum['yes','no','delayed']] $sshd_config_compression = undef,
  Array[Stdlib::Port] $sshd_config_port = [22],
  Ssh::Syslog_facility $sshd_config_syslog_facility = 'AUTH',
  String $sshd_config_template = 'ssh/sshd_config.erb',
  String $sshd_config_login_grace_time = '120',
  Ssh::Yes_no $sshd_config_challenge_resp_auth = 'yes',
  Ssh::Yes_no $sshd_config_print_motd = 'yes',
  Optional[Ssh::Yes_no] $sshd_config_print_last_log = undef,
  Optional[Ssh::Yes_no] $sshd_config_use_dns = undef,
  Optional[String] $sshd_config_authkey_location = undef,
  Optional[Ssh::Yes_no] $sshd_config_strictmodes = undef,
  Optional[String] $sshd_config_serverkeybits = undef,
  Optional[Stdlib::Absolutepath] $sshd_config_banner = undef,
  Optional[Array[String]] $sshd_config_ciphers = undef,
  Optional[Array[String]] $sshd_config_kexalgorithms = undef,
  Optional[Array[String]] $sshd_config_macs = undef,
  Optional[Ssh::Yes_no] $ssh_enable_ssh_keysign = undef,
  Array[String] $sshd_config_allowgroups = [],
  Array[String] $sshd_config_allowusers = [],
  Array[String] $sshd_config_denygroups = [],
  Array[String] $sshd_config_denyusers = [],
  Optional[Integer] $sshd_config_maxauthtries = undef,
  Optional[Pattern[/^((\d+)|(\d+?:\d+?:\d+)?)$/]] $sshd_config_maxstartups = undef,
  Optional[Integer] $sshd_config_maxsessions = undef,
  Optional[Stdlib::Absolutepath] $sshd_config_chrootdirectory = undef,
  Optional[String] $sshd_config_forcecommand = undef,
  Optional[Hash] $sshd_config_match = undef,
  Optional[Stdlib::Absolutepath] $sshd_authorized_keys_command = undef,
  Optional[String] $sshd_authorized_keys_command_user = undef,
  Optional[String] $sshd_banner_content = undef,
  String $sshd_banner_owner = 'root',
  String $sshd_banner_group = 'root',
  Stdlib::Filemode $sshd_banner_mode = '0644',
  Optional[Stdlib::Absolutepath] $sshd_config_xauth_location = undef,
  String $sshd_config_subsystem_sftp = '/usr/lib/openssh/sftp-server',
  Optional[Ssh::Yes_no] $sshd_kerberos_authentication = undef,
  Ssh::Yes_no $sshd_password_authentication = 'yes',
  Ssh::Yes_no $sshd_allow_tcp_forwarding = 'yes',
  Ssh::Yes_no $sshd_x11_forwarding = 'yes',
  Ssh::Yes_no $sshd_x11_use_localhost = 'yes',
  Optional[Ssh::Yes_no] $sshd_use_pam = undef,
  Integer $sshd_client_alive_count_max = 3,
  Integer $sshd_client_alive_interval = 0,
  Ssh::Yes_no $sshd_gssapiauthentication = 'yes',
  Optional[Ssh::Yes_no] $sshd_gssapikeyexchange = undef,
  Optional[Ssh::Yes_no] $sshd_pamauthenticationviakbdint = undef,
  Optional[Ssh::Yes_no] $sshd_gssapicleanupcredentials = undef,
  Boolean $sshd_acceptenv = true,
  Optional[Array[Stdlib::Absolutepath]] $sshd_config_hostkey = ['/etc/ssh/ssh_host_rsa_key'],
  Optional[Array[String]] $sshd_listen_address = undef,
  Ssh::Yes_no $sshd_hostbasedauthentication = 'no',
  Optional[Array[String]] $sshd_pubkeyacceptedkeytypes = undef,
  Ssh::Yes_no $sshd_pubkeyauthentication = 'yes',
  Ssh::Yes_no $sshd_ignoreuserknownhosts = 'no',
  Ssh::Yes_no $sshd_ignorerhosts = 'yes',
  Optional[Array[String]] $sshd_config_authenticationmethods = undef,
  Boolean $manage_service = true,
  Optional[Pattern[/^(any|inet|inet6)$/]] $sshd_addressfamily = undef,
  String $service_ensure = 'running',
  String $service_name = 'sshd',
  Boolean $service_enable = true,
  Boolean $service_hasrestart = true,
  Optional[Boolean] $service_hasstatus = true,
  String $ssh_key_ensure = 'present',
  Boolean $ssh_key_import = true,
  String $ssh_key_type = 'ssh-rsa',
  Stdlib::Absolutepath $ssh_config_global_known_hosts_file = '/etc/ssh/ssh_known_hosts',
  Optional[Array[Stdlib::Absolutepath]] $ssh_config_global_known_hosts_list = undef,
  String $ssh_config_global_known_hosts_owner = 'root',
  String $ssh_config_global_known_hosts_group = 'root',
  Stdlib::Filemode $ssh_config_global_known_hosts_mode = '0644',
  Optional[Array[String]] $ssh_config_user_known_hosts_file = undef,
  Hash $config_entries = {},
  Optional[Hash] $keys = undef,
  Boolean $manage_root_ssh_config = false,
  String $root_ssh_config_content = "# This file is being maintained by Puppet.\n# DO NOT EDIT\n",
  Optional[Ssh::Yes_no] $sshd_config_tcp_keepalive              = undef,
  Optional[Enum['yes','no','sandbox']] $sshd_config_use_privilege_separation   = undef,
  Optional[Enum['yes','no','point-to-point','ethernet']] $sshd_config_permittunnel = undef,
  Optional[Array[Stdlib::Absolutepath]] $sshd_config_hostcertificate = undef,
  Optional[Stdlib::Absolutepath] $sshd_config_trustedusercakeys = undef,
  Optional[Stdlib::Absolutepath] $sshd_config_key_revocation_list = undef,
  Optional[String] $sshd_config_authorized_principals_file = undef,
  Optional[Ssh::Yes_no] $sshd_config_allowagentforwarding = undef,
) {

  if "${::ssh_version}" =~ /^OpenSSH/  { # lint:ignore:only_variable_string
    $ssh_version_array = split($::ssh_version_numeric, '\.')
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
      $key = $::sshrsakey
    }
    'ssh-dsa','dsa': {
      $key = $::sshdsakey
    }
    'ecdsa-sha2-nistp256': {
          $key = $::sshecdsakey
    }
    default: {
      fail("ssh::ssh_key_type must be 'ecdsa-sha2-nistp256', 'ssh-rsa', 'rsa', 'ssh-dsa', or 'dsa' and is <${ssh_key_type}>.")
    }
  }

  $ssh_config_global_known_hosts_file_real = any2array($ssh_config_global_known_hosts_file)

  if $ssh_config_global_known_hosts_list != undef {
    $ssh_config_global_known_hosts_list_real = concat($ssh_config_global_known_hosts_file_real, $ssh_config_global_known_hosts_list)
  } else {
    $ssh_config_global_known_hosts_list_real = $ssh_config_global_known_hosts_file_real
  }

  $supported_loglevel_vals=['QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE']

  #enable hiera merging for groups, users, and config_entries
  if $hiera_merge == true {
    $sshd_config_allowgroups_real = hiera_array('ssh::sshd_config_allowgroups',[])
    $sshd_config_allowusers_real  = hiera_array('ssh::sshd_config_allowusers',[])
    $sshd_config_denygroups_real  = hiera_array('ssh::sshd_config_denygroups',[])
    $sshd_config_denyusers_real   = hiera_array('ssh::sshd_config_denyusers',[])
    $config_entries_real          = hiera_hash('ssh::config_entries',{})
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

  file  { 'ssh_config' :
    ensure  => file,
    path    => $ssh_config_path,
    owner   => $ssh_config_owner,
    group   => $ssh_config_group,
    mode    => $ssh_config_mode,
    content => template($ssh_config_template),
    require => Package[$packages],
  }

  file  { 'sshd_config' :
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
      path   => "${::root_home}/.ssh",
      owner  => 'root',
      group  => 'root',
      mode   => '0700',
    }

    file { 'root_ssh_config':
      ensure  => file,
      path    => "${::root_home}/.ssh/config",
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
    firewall { '22 open port 22 for SSH':
      action => 'accept',
      dport  => 22,
      proto  => 'tcp',
    }
  }

  # If either IPv4 or IPv6 stack is not configured on the agent, the
  # corresponding $::ipaddress(6)? fact is not present. So, we cannot assume
  # these variables are defined. Getvar (Stdlib 4.13+, ruby 1.8.7+) handles
  # this correctly.
  if getvar('::ipaddress') and getvar('::ipaddress6') { $host_aliases = [$::hostname, $::ipaddress, $::ipaddress6] }
  elsif getvar('::ipaddress6') { $host_aliases = [$::hostname, $::ipaddress6] }
  else { $host_aliases = [$::hostname, $::ipaddress] }

  # export each node's ssh key
  @@sshkey { $::fqdn :
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
  resources  { 'sshkey':
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
