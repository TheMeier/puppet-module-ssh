# == Class: ssh
#
# Manage ssh client and server
#
class ssh (
  Boolean $hiera_merge = false,
  String $packages = 'USE_DEFAULTS',
  String $permit_root_login = 'yes',
  Boolean $purge_keys = true,
  Boolean $manage_firewall = false,
  Optional[Stdlib::Absolutepath] $ssh_package_source = undef,
  Optional[Stdlib::Absolutepath] $ssh_package_adminfile = undef,
  Optional[Enum['yes','no']] $ssh_config_hash_known_hosts = undef,
  String $ssh_config_path = '/etc/ssh/ssh_config',
  String $ssh_config_owner = 'root',
  String $ssh_config_group = 'root',
  Stdlib::Filemode $ssh_config_mode = '0644',
  Optional[String] $ssh_config_forward_x11 = undef,
  Optional[Enum['yes','no']] $ssh_config_forward_x11_trusted = undef,
  Optional[String] $ssh_config_forward_agent = undef,
  Optional[String] $ssh_config_server_alive_interval = undef,
  Boolean $ssh_config_sendenv_xmodifiers = false,
  Optional[Enum['yes','no']] $ssh_hostbasedauthentication = undef,
  Optional[String] $ssh_config_proxy_command = undef,
  Optional[Enum['yes','no','ask']] $ssh_strict_host_key_checking = undef,
  Optional[Array[String]] $ssh_config_ciphers = undef,
  Optional[Array[String]] $ssh_config_kexalgorithms = undef,
  Optional[Array[String]] $ssh_config_macs = undef,
  Optional[Enum['yes','no','unset']] $ssh_config_use_roaming = undef,
  String $ssh_config_template = 'ssh/ssh_config.erb',
  Optional[Boolean] $ssh_sendenv = undef,
  Optional[Enum['yes','no']] $ssh_gssapiauthentication = 'yes',
  Optional[Enum['yes','no']] $ssh_gssapidelegatecredentials = undef,
  String $sshd_config_path = '/etc/ssh/sshd_config',
  String $sshd_config_owner = 'root',
  String $sshd_config_group = 'root',
  Enum['QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE'] $sshd_config_loglevel = 'INFO',
  String $sshd_config_mode = 'USE_DEFAULTS',
  Optional[Enum['yes','no']] $sshd_config_permitemptypasswords = undef,
  Optional[Enum['yes','no']] $sshd_config_permituserenvironment = undef,
  Optional[Enum['yes','no','delayed']] $sshd_config_compression = undef,
  Array[Stdlib::Port] $sshd_config_port = [22],
  String $sshd_config_syslog_facility = 'AUTH',
  String $sshd_config_template = 'ssh/sshd_config.erb',
  String $sshd_config_login_grace_time = '120',
  String $sshd_config_challenge_resp_auth = 'yes',
  String $sshd_config_print_motd = 'yes',
  Optional[Enum['yes','no']] $sshd_config_print_last_log = undef,
  String $sshd_config_use_dns = 'USE_DEFAULTS',
  Optional[String] $sshd_config_authkey_location = undef,
  Optional[Enum['yes','no']] $sshd_config_strictmodes = undef,
  String $sshd_config_serverkeybits = 'USE_DEFAULTS',
  Optional[Stdlib::Absolutepath] $sshd_config_banner = undef,
  Optional[Array[String]] $sshd_config_ciphers = undef,
  Optional[Array[String]] $sshd_config_kexalgorithms = undef,
  Optional[Array[String]] $sshd_config_macs = undef,
  Optional[Enum['yes','no']] $ssh_enable_ssh_keysign = undef,
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
  String $sshd_config_subsystem_sftp = 'USE_DEFAULTS',
  Optional[Enum['yes','no']] $sshd_kerberos_authentication = undef,
  Enum['yes','no'] $sshd_password_authentication = 'yes',
  Enum['yes','no'] $sshd_allow_tcp_forwarding = 'yes',
  Enum['yes','no'] $sshd_x11_forwarding = 'yes',
  Enum['yes','no'] $sshd_x11_use_localhost = 'yes',
  Optional[Enum['yes','no']] $sshd_use_pam = undef,
  String $sshd_client_alive_count_max = '3',
  String $sshd_client_alive_interval = '0',
  Enum['yes','no'] $sshd_gssapiauthentication = 'yes',
  Optional[Enum['yes','no']] $sshd_gssapikeyexchange = undef,
  Optional[Enum['yes','no']] $sshd_pamauthenticationviakbdint = undef,
  Optional[Enum['yes','no']] $sshd_gssapicleanupcredentials = undef,
  Optional[Boolean] $sshd_acceptenv = undef,
  Optional[Array[Stdlib::Absolutepath]] $sshd_config_hostkey = undef,
  Optional[Array[String]] $sshd_listen_address = undef,
  Enum['yes','no'] $sshd_hostbasedauthentication = 'no',
  Optional[Array[String]] $sshd_pubkeyacceptedkeytypes = undef,
  Enum['yes','no'] $sshd_pubkeyauthentication = 'yes',
  Enum['yes','no'] $sshd_ignoreuserknownhosts = 'no',
  Enum['yes','no'] $sshd_ignorerhosts = 'yes',
  Optional[Array[String]] $sshd_config_authenticationmethods = undef,
  Boolean $manage_service = true,
  Optional[Pattern[/^(any|inet|inet6)$/]] $sshd_addressfamily = undef,
  String $service_ensure = 'running',
  String $service_name = 'USE_DEFAULTS',
  Boolean $service_enable = true,
  Boolean $service_hasrestart = true,
  Optional[Boolean] $service_hasstatus = undef,
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
  Optional[Enum['yes','no']] $sshd_config_tcp_keepalive              = undef,
  Optional[Enum['yes','no','sandbox']] $sshd_config_use_privilege_separation   = undef,
  Optional[Enum['yes','no','point-to-point','ethernet','unset']] $sshd_config_permittunnel = undef,
  Optional[Array[Stdlib::Absolutepath]] $sshd_config_hostcertificate = undef,
  Optional[Stdlib::Absolutepath] $sshd_config_trustedusercakeys = undef,
  Optional[Stdlib::Absolutepath] $sshd_config_key_revocation_list = undef,
  Optional[String] $sshd_config_authorized_principals_file = undef,
  Optional[Enum['yes','no']] $sshd_config_allowagentforwarding = undef,
) {

  case $::osfamily {
    'RedHat': {
      $default_packages                        = ['openssh-server',
                                                  'openssh-clients']
      $default_service_name                    = 'sshd'
      $default_ssh_config_hash_known_hosts     = 'no'
      $default_ssh_config_forward_x11_trusted  = 'yes'
      $default_ssh_package_source              = undef
      $default_ssh_package_adminfile           = undef
      $default_ssh_sendenv                     = true
      $default_sshd_config_subsystem_sftp      = '/usr/libexec/openssh/sftp-server'
      $default_sshd_config_mode                = '0600'
      $default_sshd_config_use_dns             = 'yes'
      $default_sshd_config_xauth_location      = '/usr/bin/xauth'
      $default_sshd_use_pam                    = 'yes'
      $default_sshd_gssapikeyexchange          = undef
      $default_sshd_pamauthenticationviakbdint = undef
      $default_sshd_gssapicleanupcredentials   = 'yes'
      $default_sshd_acceptenv                  = true
      $default_service_hasstatus               = true
      if versioncmp($::operatingsystemrelease, '7.4') < 0 {
        $default_sshd_config_serverkeybits = '1024'
      } else {
        $default_sshd_config_serverkeybits = undef
      }
      $default_sshd_config_hostkey             = [ '/etc/ssh/ssh_host_rsa_key' ]
      $default_sshd_addressfamily              = 'any'
      $default_sshd_config_tcp_keepalive       = 'yes'
      $default_sshd_config_permittunnel        = 'no'
    }
    'Suse': {
      $default_packages                        = 'openssh'
      $default_service_name                    = 'sshd'
      $default_ssh_config_hash_known_hosts     = 'no'
      $default_ssh_package_source              = undef
      $default_ssh_package_adminfile           = undef
      $default_ssh_sendenv                     = true
      $default_ssh_config_forward_x11_trusted  = 'yes'
      $default_sshd_config_mode                = '0600'
      $default_sshd_config_use_dns             = 'yes'
      $default_sshd_config_xauth_location      = '/usr/bin/xauth'
      $default_sshd_use_pam                    = 'yes'
      $default_sshd_gssapikeyexchange          = undef
      $default_sshd_pamauthenticationviakbdint = undef
      $default_sshd_gssapicleanupcredentials   = 'yes'
      $default_sshd_acceptenv                  = true
      $default_service_hasstatus               = true
      $default_sshd_config_serverkeybits       = '1024'
      $default_sshd_config_hostkey             = [ '/etc/ssh/ssh_host_rsa_key' ]
      $default_sshd_addressfamily              = 'any'
      $default_sshd_config_tcp_keepalive       = 'yes'
      $default_sshd_config_permittunnel        = 'no'
      case $::architecture {
        'x86_64': {
          if ($::operatingsystem == 'SLES') and ($::operatingsystemrelease =~ /^12\./) {
            $default_sshd_config_subsystem_sftp = '/usr/lib/ssh/sftp-server'
          } else {
            $default_sshd_config_subsystem_sftp = '/usr/lib64/ssh/sftp-server'
          }
        }
        'i386' : {
          $default_sshd_config_subsystem_sftp = '/usr/lib/ssh/sftp-server'
      }
        default: {
          fail("ssh supports architectures x86_64 and i386 for Suse. Detected architecture is <${::architecture}>.")
        }
      }
    }
    'Debian': {
      # common for debian and ubuntu
      $default_packages                        = ['openssh-server',
                                                  'openssh-client']
      $default_service_name                    = 'ssh'

      case $::operatingsystemrelease {
        '16.04': {
          $default_sshd_config_hostkey = [
            '/etc/ssh/ssh_host_rsa_key',
            '/etc/ssh/ssh_host_dsa_key',
            '/etc/ssh/ssh_host_ecdsa_key',
            '/etc/ssh/ssh_host_ed25519_key',
          ]
          $default_ssh_config_hash_known_hosts        = 'yes'
          $default_sshd_config_xauth_location         = undef
          $default_ssh_config_forward_x11_trusted     = 'yes'
          $default_ssh_package_source                 = undef
          $default_ssh_package_adminfile              = undef
          $default_ssh_sendenv                        = true
          $default_sshd_config_subsystem_sftp         = '/usr/lib/openssh/sftp-server'
          $default_sshd_config_mode                   = '0600'
          $default_sshd_config_use_dns                = 'yes'
          $default_sshd_use_pam                       = 'yes'
          $default_sshd_gssapikeyexchange             = undef
          $default_sshd_pamauthenticationviakbdint    = undef
          $default_sshd_gssapicleanupcredentials      = 'yes'
          $default_sshd_acceptenv                     = true
          $default_service_hasstatus                  = true
          $default_sshd_config_serverkeybits          = '1024'
          $default_sshd_addressfamily                 = 'any'
          $default_sshd_config_tcp_keepalive          = 'yes'
          $default_sshd_config_permittunnel           = 'no'
        }
        '18.04': {
          $default_sshd_config_hostkey = [
            '/etc/ssh/ssh_host_rsa_key',
            '/etc/ssh/ssh_host_dsa_key',
            '/etc/ssh/ssh_host_ecdsa_key',
            '/etc/ssh/ssh_host_ed25519_key',
          ]
          $default_ssh_config_hash_known_hosts        = 'yes'
          $default_sshd_config_xauth_location         = undef
          $default_ssh_config_forward_x11_trusted     = 'yes'
          $default_ssh_package_source                 = undef
          $default_ssh_package_adminfile              = undef
          $default_ssh_sendenv                        = true
          $default_sshd_config_subsystem_sftp         = '/usr/lib/openssh/sftp-server'
          $default_sshd_config_mode                   = '0600'
          $default_sshd_config_use_dns                = 'yes'
          $default_sshd_use_pam                       = 'yes'
          $default_sshd_gssapikeyexchange             = undef
          $default_sshd_pamauthenticationviakbdint    = undef
          $default_sshd_gssapicleanupcredentials      = 'yes'
          $default_sshd_acceptenv                     = true
          $default_service_hasstatus                  = true
          $default_sshd_config_serverkeybits          = '1024'
          $default_sshd_addressfamily                 = 'any'
          $default_sshd_config_tcp_keepalive          = 'yes'
          $default_sshd_config_permittunnel           = 'no'
        }
        /^(9|10).*/: {
          $default_sshd_config_hostkey = [
            '/etc/ssh/ssh_host_rsa_key',
            '/etc/ssh/ssh_host_ecdsa_key',
            '/etc/ssh/ssh_host_ed25519_key',
          ]
          $default_sshd_config_mode                = '0600'
          $default_sshd_use_pam                    = 'yes'
          $default_ssh_config_forward_x11_trusted  = 'yes'
          $default_sshd_acceptenv                  = true
          $default_sshd_config_subsystem_sftp      = '/usr/lib/openssh/sftp-server'
          $default_ssh_config_hash_known_hosts     = 'yes'
          $default_ssh_sendenv                     = true
          $default_sshd_addressfamily              = undef
          $default_sshd_config_serverkeybits       = undef
          $default_sshd_gssapicleanupcredentials   = undef
          $default_sshd_config_use_dns             = undef
          $default_sshd_config_xauth_location      = undef
          $default_sshd_config_permittunnel        = undef
          $default_sshd_config_tcp_keepalive       = undef
          $default_ssh_package_source              = undef
          $default_ssh_package_adminfile           = undef
          $default_sshd_gssapikeyexchange          = undef
          $default_sshd_pamauthenticationviakbdint = undef
          $default_service_hasstatus               = true
        }
        /^7.*/: {
          $default_sshd_config_hostkey             = [ '/etc/ssh/ssh_host_rsa_key' ]
          $default_ssh_config_hash_known_hosts     = 'no'
          $default_sshd_config_xauth_location      = '/usr/bin/xauth'
          $default_ssh_config_forward_x11_trusted  = 'yes'
          $default_ssh_package_source              = undef
          $default_ssh_package_adminfile           = undef
          $default_ssh_sendenv                     = true
          $default_sshd_config_subsystem_sftp      = '/usr/lib/openssh/sftp-server'
          $default_sshd_config_mode                = '0600'
          $default_sshd_config_use_dns             = 'yes'
          $default_sshd_use_pam                    = 'yes'
          $default_sshd_gssapikeyexchange          = undef
          $default_sshd_pamauthenticationviakbdint = undef
          $default_sshd_gssapicleanupcredentials   = 'yes'
          $default_sshd_acceptenv                  = true
          $default_service_hasstatus               = true
          $default_sshd_config_serverkeybits       = '1024'
          $default_sshd_addressfamily              = 'any'
          $default_sshd_config_tcp_keepalive       = 'yes'
          $default_sshd_config_permittunnel        = 'no'
        }
        /^8.*/: {

          $default_ssh_config_hash_known_hosts     = 'yes'
          $default_ssh_config_forward_x11_trusted  = 'yes'
          $default_ssh_package_source              = undef
          $default_ssh_package_adminfile           = undef
          $default_ssh_sendenv                     = true
          $default_sshd_config_hostkey = [
          '/etc/ssh/ssh_host_rsa_key',
          '/etc/ssh/ssh_host_dsa_key',
          '/etc/ssh/ssh_host_ecdsa_key',
          '/etc/ssh/ssh_host_ed25519_key',
          ]
          $default_sshd_config_subsystem_sftp      = '/usr/lib/openssh/sftp-server'
          $default_sshd_config_mode                = '0600'
          $default_sshd_config_use_dns             = 'yes'
          $default_sshd_use_pam                    = 'yes'
          $default_sshd_gssapikeyexchange          = undef
          $default_sshd_pamauthenticationviakbdint = undef
          $default_sshd_gssapicleanupcredentials   = undef
          $default_sshd_acceptenv                  = true
          $default_sshd_config_xauth_location      = undef
          $default_sshd_config_serverkeybits       = '1024'
          $default_sshd_addressfamily              = 'any'
          $default_sshd_config_tcp_keepalive       = 'yes'
          $default_sshd_config_permittunnel        = 'no'
          $default_service_hasstatus               = true
        }
        default: { fail ("Operating System : ${::operatingsystemrelease} not supported") }
      }
    }
    'Solaris': {
      $default_ssh_config_hash_known_hosts     = undef
      $default_ssh_sendenv                     = false
      $default_ssh_config_forward_x11_trusted  = undef
      $default_sshd_config_subsystem_sftp      = '/usr/lib/ssh/sftp-server'
      $default_sshd_config_mode                = '0644'
      $default_sshd_config_use_dns             = undef
      $default_sshd_config_xauth_location      = '/usr/openwin/bin/xauth'
      $default_sshd_use_pam                    = undef
      $default_sshd_gssapikeyexchange          = 'yes'
      $default_sshd_pamauthenticationviakbdint = 'yes'
      $default_sshd_gssapicleanupcredentials   = undef
      $default_sshd_acceptenv                  = false
      $default_sshd_config_serverkeybits       = '768'
      $default_ssh_package_adminfile           = undef
      $default_sshd_config_hostkey             = [ '/etc/ssh/ssh_host_rsa_key' ]
      $default_sshd_addressfamily              = undef
      $default_sshd_config_tcp_keepalive       = undef
      $default_sshd_config_permittunnel        = undef
      case $::kernelrelease {
        '5.11': {
          $default_packages                      = ['network/ssh',
                                                    'network/ssh/ssh-key',
                                                    'service/network/ssh']
          $default_service_name                  = 'ssh'
          $default_service_hasstatus             = true
          $default_ssh_package_source            = undef
        }
        '5.10': {
          $default_packages                      = ['SUNWsshcu',
                                                    'SUNWsshdr',
                                                    'SUNWsshdu',
                                                    'SUNWsshr',
                                                    'SUNWsshu']
          $default_service_name                  = 'ssh'
          $default_service_hasstatus             = true
          $default_ssh_package_source            = '/var/spool/pkg'
        }
        '5.9' : {
          $default_packages                      = ['SUNWsshcu',
                                                    'SUNWsshdr',
                                                    'SUNWsshdu',
                                                    'SUNWsshr',
                                                    'SUNWsshu']
          $default_service_name                  = 'sshd'
          $default_service_hasstatus             = false
          $default_ssh_package_source            = '/var/spool/pkg'
        }
        default: {
          fail('ssh module supports Solaris kernel release 5.9, 5.10 and 5.11.')
        }
      }
    }
    default: {
      fail("ssh supports osfamilies RedHat, Suse, Debian and Solaris. Detected osfamily is <${::osfamily}>.")
    }
  }

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

  if $packages == 'USE_DEFAULTS' {
    $packages_real = $default_packages
  } else {
    $packages_real = $packages
  }

  case $ssh_config_hash_known_hosts {
    undef:   { $ssh_config_hash_known_hosts_real = $default_ssh_config_hash_known_hosts }
    default: { $ssh_config_hash_known_hosts_real = $ssh_config_hash_known_hosts }
  }

  if $service_name == 'USE_DEFAULTS' {
    $service_name_real = $default_service_name
  } else {
    $service_name_real = $service_name
  }

  if $sshd_config_subsystem_sftp == 'USE_DEFAULTS' {
    $sshd_config_subsystem_sftp_real = $default_sshd_config_subsystem_sftp
  } else {
    $sshd_config_subsystem_sftp_real = $sshd_config_subsystem_sftp
  }

  if $sshd_config_mode    == 'USE_DEFAULTS' {
    $sshd_config_mode_real = $default_sshd_config_mode
  } else {
    $sshd_config_mode_real = $sshd_config_mode
  }

  if $sshd_config_xauth_location == undef {
    $sshd_config_xauth_location_real = $default_sshd_config_xauth_location
  } else {
    $sshd_config_xauth_location_real = $sshd_config_xauth_location
  }
  assert_type(Optional[Stdlib::Absolutepath], $sshd_config_xauth_location_real)


  if $ssh_package_source == undef {
    $ssh_package_source_real = $default_ssh_package_source
  } else {
    $ssh_package_source_real = $ssh_package_source
  }
  assert_type(Optional[Stdlib::Absolutepath], $ssh_package_source_real)

  if $ssh_package_adminfile == undef {
    $ssh_package_adminfile_real = $default_ssh_package_adminfile
  } else {
    $ssh_package_adminfile_real = $ssh_package_adminfile
  }
  assert_type(Optional[Stdlib::Absolutepath], $ssh_package_adminfile_real)

  if $sshd_config_use_dns == 'USE_DEFAULTS' {
    $sshd_config_use_dns_real = $default_sshd_config_use_dns
  } else {
    $sshd_config_use_dns_real = $sshd_config_use_dns
  }

  case $sshd_use_pam {
    undef:   { $sshd_use_pam_real = $default_sshd_use_pam }
    default: { $sshd_use_pam_real = $sshd_use_pam }
  }

  if $sshd_config_serverkeybits == 'USE_DEFAULTS' {
    $sshd_config_serverkeybits_real = $default_sshd_config_serverkeybits
  } else {
    $sshd_config_serverkeybits_real = $sshd_config_serverkeybits
  }

  if $ssh_config_forward_x11_trusted {
    $ssh_config_forward_x11_trusted_real = $ssh_config_forward_x11_trusted
  } else {
    $ssh_config_forward_x11_trusted_real = $default_ssh_config_forward_x11_trusted
  }
  assert_type(Optional[Enum['yes','no']], $ssh_config_forward_x11_trusted_real)

  if $sshd_gssapikeyexchange {
    $sshd_gssapikeyexchange_real = $sshd_gssapikeyexchange
  } else {
    $sshd_gssapikeyexchange_real = $default_sshd_gssapikeyexchange
  }
  assert_type(Optional[Enum['yes','no']], $sshd_gssapikeyexchange_real)

  if $sshd_pamauthenticationviakbdint {
    $sshd_pamauthenticationviakbdint_real = $sshd_pamauthenticationviakbdint
  } else {
    $sshd_pamauthenticationviakbdint_real = $default_sshd_pamauthenticationviakbdint
  }
  assert_type(Optional[Enum['yes','no']], $sshd_pamauthenticationviakbdint_real)


  if $sshd_gssapicleanupcredentials {
    $sshd_gssapicleanupcredentials_real = $sshd_gssapicleanupcredentials
  } else {
    $sshd_gssapicleanupcredentials_real = $default_sshd_gssapicleanupcredentials
  }
  assert_type(Optional[Enum['yes','no']], $sshd_gssapicleanupcredentials_real)

  if $ssh_config_use_roaming == undef {
    $ssh_config_use_roaming_real = $default_ssh_config_use_roaming
  } else {
    $ssh_config_use_roaming_real = $ssh_config_use_roaming
  }

  if $ssh_sendenv != undef {
    $ssh_sendenv_real = $ssh_sendenv
  } else {
    $ssh_sendenv_real = $default_ssh_sendenv
  }

  if $sshd_acceptenv != undef {
    $sshd_acceptenv_real = $sshd_acceptenv
  } else {
    $sshd_acceptenv_real = $default_sshd_acceptenv
  }


  if $sshd_config_hostkey {
    $sshd_config_hostkey_real = $sshd_config_hostkey
  } else {
    $sshd_config_hostkey_real = $default_sshd_config_hostkey
  }

  if $service_hasstatus != undef {
    $service_hasstatus_real = $service_hasstatus
  } else {
    $service_hasstatus_real = $default_service_hasstatus
  }

  if $sshd_addressfamily != undef {
    $sshd_addressfamily_real = $sshd_addressfamily
  } else {
    $sshd_addressfamily_real = $default_sshd_addressfamily
  }

  case $sshd_config_maxsessions {
    undef: { $sshd_config_maxsessions_integer = undef }
    default:        { $sshd_config_maxsessions_integer = floor($sshd_config_maxsessions) }
  }

  case $sshd_config_tcp_keepalive {
    undef:   { $sshd_config_tcp_keepalive_real = $default_sshd_config_tcp_keepalive }
    default: { $sshd_config_tcp_keepalive_real = $sshd_config_tcp_keepalive }
  }

  case $sshd_config_permittunnel {
    'unset': { $sshd_config_permittunnel_real = undef }
    undef:   { $sshd_config_permittunnel_real = $default_sshd_config_permittunnel }
    default: { $sshd_config_permittunnel_real = $sshd_config_permittunnel }
  }

  case $sshd_config_hostcertificate {
    'unset', undef: { $sshd_config_hostcertificate_real = undef }
    default: { $sshd_config_hostcertificate_real = $sshd_config_hostcertificate }
  }

  if $sshd_config_serverkeybits_real != undef {
    if is_integer($sshd_config_serverkeybits_real) == false { fail("ssh::sshd_config_serverkeybits must be an integer and is set to <${sshd_config_serverkeybits}>.") }
  }

  if is_integer($sshd_client_alive_interval) == false { fail("ssh::sshd_client_alive_interval must be an integer and is set to <${sshd_client_alive_interval}>.") }
  if is_integer($sshd_client_alive_count_max) == false { fail("ssh::sshd_client_alive_count_max must be an integer and is set to <${sshd_client_alive_count_max}>.") }

  if $sshd_banner_content != undef and $sshd_config_banner == undef {
    fail('ssh::sshd_config_banner must be set to be able to use sshd_banner_content.')
  }

  case $permit_root_login {
    'no', 'yes', 'without-password', 'forced-commands-only': {
      # noop
    }
    default: {
      fail("ssh::permit_root_login may be either 'yes', 'without-password', 'forced-commands-only' or 'no' and is set to <${permit_root_login}>.")
    }
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

  package { $packages_real:
    ensure    => installed,
    source    => $ssh_package_source_real,
    adminfile => $ssh_package_adminfile_real,
  }

  file  { 'ssh_config' :
    ensure  => file,
    path    => $ssh_config_path,
    owner   => $ssh_config_owner,
    group   => $ssh_config_group,
    mode    => $ssh_config_mode,
    content => template($ssh_config_template),
    require => Package[$packages_real],
  }

  file  { 'sshd_config' :
    ensure  => file,
    path    => $sshd_config_path,
    mode    => $sshd_config_mode_real,
    owner   => $sshd_config_owner,
    group   => $sshd_config_group,
    content => template($sshd_config_template),
    require => Package[$packages_real],
  }

  if $sshd_config_banner != undef and $sshd_banner_content != undef {
    file { 'sshd_banner' :
      ensure  => file,
      path    => $sshd_config_banner,
      owner   => $sshd_banner_owner,
      group   => $sshd_banner_group,
      mode    => $sshd_banner_mode,
      content => $sshd_banner_content,
      require => Package[$packages_real],
    }
  }

  if $manage_root_ssh_config == true {

    include ::common

    common::mkdir_p { "${::root_home}/.ssh": }

    file { 'root_ssh_dir':
      ensure  => directory,
      path    => "${::root_home}/.ssh",
      owner   => 'root',
      group   => 'root',
      mode    => '0700',
      require => Common::Mkdir_p["${::root_home}/.ssh"],
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
      name       => $service_name_real,
      enable     => $service_enable,
      hasrestart => $service_hasrestart,
      hasstatus  => $service_hasstatus_real,
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
    require => Package[$packages_real],
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

  if $sshd_addressfamily_real != undef {
    if $::osfamily == 'Solaris' {
      fail("ssh::sshd_addressfamily is not supported on Solaris and is set to <${sshd_addressfamily}>.")
    }
  }
}
