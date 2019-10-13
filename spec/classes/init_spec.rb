require 'spec_helper'

describe 'ssh' do
  on_supported_os.each do |os, facts|
    ssh_version_numeric = case facts[:os]['family']
                          when 'RedHat'
                            case facts[:os]['release']['major']
                            when '5' then '4.3'
                            when '6' then '5.3'
                            else '6.6'
                            end
                          when 'Solaris' then '2.2'
                          else '6.6'
                          end
    sshd_service_hasstatus = case facts[:os]['family']
                             when 'Solaris'
                               case facts[:os]['release']['major']
                               when '9' then false
                               else true
                               end
                             else true
                             end
    facts = facts.merge(ssh_version_numeric: ssh_version_numeric)
    packages = case facts[:os]['family']
               when 'Suse' then ['openssh']
               when 'Solaris'
                 case facts[:os]['release']['major']
                 when '11' then ['network/ssh', 'network/ssh/ssh-key', 'service/network/ssh']
                 else ['SUNWsshcu', 'SUNWsshdr', 'SUNWsshdu', 'SUNWsshr', 'SUNWsshu']
                 end
               when 'RedHat' then ['openssh-server', 'openssh-clients']
               else ['openssh-server', 'openssh-client']
               end
    service_name = case facts[:os]['family']
                   when 'Debian', 'Solaris' then 'ssh'
                   else 'sshd'
                   end
    default_ssh_package_source = if facts[:os]['family'] == 'Solaris' && facts[:os]['release']['major'] == '10'
                                   '/var/spool/pkg'
                                 else
                                   nil
                                 end
    sshd_config_mode = case facts[:os]['family']
                       when 'Solaris' then '0644'
                       else '0600'
                       end
    context "with default params on osfamily #{os}" do
      let(:facts) { facts.merge(facts) }

      it { is_expected.to compile.with_all_deps }

      it { is_expected.to contain_class('ssh') }

      it { is_expected.not_to contain_class('common') }

      packages.each do |pkg|
        it {
          is_expected.to contain_package(pkg).with('ensure' => 'installed')
        }
      end

      it {
        is_expected.to contain_file('ssh_known_hosts').with('ensure' => 'file',
                                                            'path'   => '/etc/ssh/ssh_known_hosts',
                                                            'owner'  => 'root',
                                                            'group'  => 'root',
                                                            'mode'   => '0644')
      }

      packages.each do |pkg|
        it {
          is_expected.to contain_file('ssh_known_hosts').that_requires("Package[#{pkg}]")
        }
      end

      it {
        is_expected.to contain_file('ssh_config').with('ensure' => 'file',
                                                       'path'    => '/etc/ssh/ssh_config',
                                                       'owner'   => 'root',
                                                       'group'   => 'root',
                                                       'mode'    => '0644')
      }

      ssh_config_fixture = File.read(fixtures("ssh_config_#{facts[:os]['family']}_#{facts[:os]['release']['major']}"))
      it { is_expected.to contain_file('ssh_config').with_content(ssh_config_fixture) }

      packages.each do |pkg|
        it {
          is_expected.to contain_file('ssh_config').that_requires("Package[#{pkg}]")
        }
      end

      it {
        is_expected.to contain_file('sshd_config').with('ensure' => 'file',
                                                        'path'    => '/etc/ssh/sshd_config',
                                                        'owner'   => 'root',
                                                        'group'   => 'root',
                                                        'mode'    => sshd_config_mode)
      }

      packages.each do |pkg|
        it {
          is_expected.to contain_file('sshd_config').that_requires("Package[#{pkg}]")
        }
      end

      sshd_config_fixture = File.read(fixtures("sshd_config_#{facts[:os]['family']}_#{facts[:os]['release']['major']}"))
      it { is_expected.to contain_file('sshd_config').with_content(sshd_config_fixture) }

      it {
        is_expected.to contain_service('sshd_service').with('ensure' => 'running',
                                                            'name'       => service_name,
                                                            'enable'     => 'true',
                                                            'hasrestart' => 'true',
                                                            'hasstatus'  => sshd_service_hasstatus,
                                                            'subscribe'  => 'File[sshd_config]')
      }

      it {
        is_expected.to contain_resources('sshkey').with('purge' => 'true')
      }

      it { is_expected.to have_ssh__config_entry_resource_count(0) }

      context 'with exported sshkey resources' do
        subject { exported_resources }

        context 'With default facts' do
          let(:facts) { facts.merge(fqdn: 'monkey.example.com') }

          it {
            is_expected.to contain_sshkey('monkey.example.com').with(
              'ensure' => 'present',
              'host_aliases' => [facts[:hostname], '172.16.254.254', 'FE80:0000:0000:0000:AAAA:AAAA:AAAA'],
            )
          }
        end
      end
    end

    # generic tests only run for one plattform
    context 'with optional params used in ssh_config set on valid osfamily' do
      let(:facts) { facts }
      let(:params) do
        {
          ssh_config_hash_known_hosts: 'yes',
          ssh_config_forward_agent: 'yes',
          ssh_config_forward_x11: 'yes',
          ssh_config_use_roaming: 'yes',
          ssh_config_server_alive_interval: '300',
          ssh_config_sendenv_xmodifiers: true,
          ssh_config_ciphers: ['aes128-cbc',
                               '3des-cbc',
                               'blowfish-cbc',
                               'cast128-cbc',
                               'arcfour',
                               'aes192-cbc',
                               'aes256-cbc'],
          ssh_config_kexalgorithms: ['curve25519-sha256@libssh.org',
                                     'ecdh-sha2-nistp256',
                                     'ecdh-sha2-nistp384',
                                     'ecdh-sha2-nistp521',
                                     'diffie-hellman-group-exchange-sha256',
                                     'diffie-hellman-group-exchange-sha1',
                                     'diffie-hellman-group14-sha1',
                                     'diffie-hellman-group1-sha1'],
          ssh_config_macs: ['hmac-md5-etm@openssh.com',
                            'hmac-sha1-etm@openssh.com'],
          ssh_config_proxy_command: 'ssh -W %h:%p firewall.example.org',
          ssh_config_global_known_hosts_file: '/etc/ssh/ssh_known_hosts2',
          ssh_config_global_known_hosts_list: ['/etc/ssh/ssh_known_hosts3',
                                               '/etc/ssh/ssh_known_hosts4'],
          ssh_config_user_known_hosts_file: ['.ssh/known_hosts1',
                                             '.ssh/known_hosts2'],
          ssh_hostbasedauthentication: 'yes',
          ssh_strict_host_key_checking: 'ask',
          ssh_enable_ssh_keysign: 'yes',
        }
      end

      it { is_expected.to compile.with_all_deps }

      it {
        is_expected.to contain_file('ssh_config').with('ensure' => 'file',
                                                       'path'    => '/etc/ssh/ssh_config',
                                                       'owner'   => 'root',
                                                       'group'   => 'root',
                                                       'mode'    => '0644',
                                                       'require' => packages.map { |pkg| 'Package[' + pkg + ']' })
      }

      it {
        is_expected.to contain_file('ssh_config')
          .with_content(%r{^# This file is being maintained by Puppet.\n# DO NOT EDIT\n\n# \$OpenBSD: ssh_config,v 1.21 2005\/12\/06 22:38:27 reyk Exp \$})
      }
      it { is_expected.to contain_file('ssh_config').with_content(%r{^   Protocol 2$}) }
      it { is_expected.to contain_file('ssh_config').with_content(%r{^   HashKnownHosts yes$}) }
      if facts[:os]['family'] != 'Solaris'
        it { is_expected.to contain_file('ssh_config').with_content(%r{^\s*SendEnv L.*$}) }
        it { is_expected.to contain_file('ssh_config').with_content(%r{^  SendEnv XMODIFIERS$}) }
      end
      it { is_expected.to contain_file('ssh_config').with_content(%r{^  ForwardAgent yes$}) }
      it { is_expected.to contain_file('ssh_config').with_content(%r{^  ForwardX11 yes$}) }
      it { is_expected.to contain_file('ssh_config').with_content(%r{^\s*GSSAPIAuthentication yes$}) }
      it { is_expected.to contain_file('ssh_config').with_content(%r{^\s*UseRoaming yes$}) }
      it { is_expected.to contain_file('ssh_config').with_content(%r{^  ServerAliveInterval 300$}) }
      it { is_expected.to contain_file('ssh_config').with_content(%r{^\s*Ciphers aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,arcfour,aes192-cbc,aes256-cbc$}) }
      it {
        is_expected.to contain_file('ssh_config').with_content(%r{^\s*KexAlgorithms\scurve25519-sha256@libssh.org,ecdh-sha2-nistp256,
                                                                  ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,
                                                                  diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1$}x)
      }
      it { is_expected.to contain_file('ssh_config').with_content(%r{^\s*MACs hmac-md5-etm@openssh.com,hmac-sha1-etm@openssh.com$}) }
      it { is_expected.to contain_file('ssh_config').with_content(%r{^\s*ProxyCommand ssh -W %h:%p firewall\.example\.org$}) }
      it { is_expected.to contain_file('ssh_config').with_content(%r{^\s*GlobalKnownHostsFile \/etc\/ssh\/ssh_known_hosts2 \/etc\/ssh\/ssh_known_hosts3 \/etc\/ssh\/ssh_known_hosts4$}) }
      it { is_expected.to contain_file('ssh_config').with_content(%r{^\s*UserKnownHostsFile \.ssh\/known_hosts1 \.ssh\/known_hosts2$}) }
      it { is_expected.to contain_file('ssh_config').with_content(%r{^\s*HostbasedAuthentication yes$}) }
      it { is_expected.to contain_file('ssh_config').with_content(%r{^\s*StrictHostKeyChecking ask$}) }
      it { is_expected.to contain_file('ssh_config').with_content(%r{^\s*EnableSSHKeysign yes$}) }
    end

    context 'with params used in sshd_config set on valid osfamily' do
      let(:facts) { facts }
      let(:params) do
        {
          sshd_config_port: [22_222],
          sshd_config_syslog_facility: 'DAEMON',
          sshd_config_login_grace_time: '60',
          permit_root_login: 'no',
          sshd_config_chrootdirectory: '/chrootdir',
          sshd_config_forcecommand: '/force/command --with-parameter 242',
          sshd_config_match: { 'User JohnDoe' => ['AllowTcpForwarding yes'] },
          sshd_config_challenge_resp_auth: 'no',
          sshd_config_print_motd: 'no',
          sshd_config_print_last_log: 'no',
          sshd_config_use_dns: 'no',
          sshd_config_banner: '/etc/sshd_banner',
          sshd_authorized_keys_command: '/path/to/command',
          sshd_authorized_keys_command_user: 'asdf',
          sshd_banner_content: 'textinbanner',
          sshd_config_xauth_location: '/opt/ssh/bin/xauth',
          sshd_config_subsystem_sftp: '/opt/ssh/bin/sftp',
          sshd_kerberos_authentication: 'no',
          sshd_password_authentication: 'no',
          sshd_config_permitemptypasswords: 'no',
          sshd_config_permituserenvironment: 'no',
          sshd_config_compression: 'no',
          sshd_pubkeyacceptedkeytypes: ['ecdsa-sha2-nistp256',
                                        'ecdsa-sha2-nistp384',
                                        'ecdsa-sha2-nistp521',
                                        'ssh-ed25519',
                                        'ssh-rsa'],
          sshd_config_authenticationmethods: ['publickey',
                                              'keyboard-interactive'],
          sshd_pubkeyauthentication: 'no',
          sshd_allow_tcp_forwarding: 'no',
          sshd_x11_forwarding: 'no',
          sshd_x11_use_localhost: 'no',
          sshd_use_pam: 'no',
          sshd_client_alive_interval: 242,
          sshd_config_serverkeybits: '1024',
          sshd_client_alive_count_max: 0,
          sshd_config_authkey_location: '.ssh/authorized_keys',
          sshd_config_hostkey: ['/etc/ssh/ssh_host_rsa_key',
                                '/etc/ssh/ssh_host_dsa_key'],
          sshd_config_strictmodes: 'yes',
          sshd_config_ciphers: ['aes128-cbc',
                                '3des-cbc',
                                'blowfish-cbc',
                                'cast128-cbc',
                                'arcfour',
                                'aes192-cbc',
                                'aes256-cbc'],
          sshd_config_kexalgorithms: ['curve25519-sha256@libssh.org',
                                      'ecdh-sha2-nistp256',
                                      'ecdh-sha2-nistp384',
                                      'ecdh-sha2-nistp521',
                                      'diffie-hellman-group-exchange-sha256',
                                      'diffie-hellman-group-exchange-sha1',
                                      'diffie-hellman-group14-sha1',
                                      'diffie-hellman-group1-sha1'],
          sshd_config_macs: ['hmac-md5-etm@openssh.com',
                             'hmac-sha1-etm@openssh.com'],
          sshd_config_denyusers: ['root',
                                  'lusers'],
          sshd_config_denygroups: ['nossh',
                                   'wheel'],
          sshd_config_allowusers: ['foo',
                                   'bar'],
          sshd_config_allowgroups: ['ssh',
                                    'security'],
          sshd_listen_address: ['192.168.1.1',
                                '2001:db8::dead:f00d'],
          sshd_config_tcp_keepalive: 'yes',
          sshd_config_use_privilege_separation: 'no',
          sshd_config_permittunnel: 'no',
          sshd_config_allowagentforwarding: 'no',
          sshd_config_key_revocation_list: '/path/to/revocation_list',
          sshd_gssapicleanupcredentials: 'yes',
        }
      end

      it { is_expected.to compile.with_all_deps }

      it {
        is_expected.to contain_file('sshd_config').with('ensure'  => 'file',
                                                        'path'    => '/etc/ssh/sshd_config',
                                                        'owner'   => 'root',
                                                        'group'   => 'root',
                                                        'mode'    => sshd_config_mode,
                                                        'require' => packages.map { |pkg| 'Package[' + pkg + ']' })
      }

      it { is_expected.to contain_file('sshd_config').with_content(%r{^Port 22222$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^SyslogFacility DAEMON$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^LogLevel INFO$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^LoginGraceTime 60$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^PermitRootLogin no$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^ChallengeResponseAuthentication no$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^PrintMotd no$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^PrintLastLog no$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^UseDNS no$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{Banner \/etc\/sshd_banner$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{XAuthLocation \/opt\/ssh\/bin\/xauth$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{Subsystem sftp \/opt\/ssh\/bin\/sftp$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^PasswordAuthentication no$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^KerberosAuthentication no$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^AllowTcpForwarding no$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^X11Forwarding no$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^X11UseLocalhost no$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^UsePAM no$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^ClientAliveInterval 242$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^ServerKeyBits 1024$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^ClientAliveCountMax 0$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^GSSAPIAuthentication yes$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^GSSAPICleanupCredentials yes$}) }
      if facts[:os]['family'] != 'Solaris'
        it { is_expected.not_to contain_file('sshd_config').with_content(%r{^\s*PAMAuthenticationViaKBDInt yes$}) }
        it { is_expected.not_to contain_file('sshd_config').with_content(%r{^\s*GSSAPIKeyExchange yes$}) }
        it { is_expected.to contain_file('sshd_config').with_content(%r{^AcceptEnv L.*$}) }
      end
      it { is_expected.to contain_file('sshd_config').with_content(%r{^AuthorizedKeysFile .ssh\/authorized_keys}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^HostKey \/etc\/ssh\/ssh_host_rsa_key}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^HostKey \/etc\/ssh\/ssh_host_dsa_key}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^StrictModes yes$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^PermitUserEnvironment no}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^Compression no$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^PermitEmptyPasswords no}) }
      it { is_expected.not_to contain_file('sshd_config').with_content(%r{^MaxAuthTries}) }
      it { is_expected.not_to contain_file('sshd_config').with_content(%r{^MaxStartups}) }
      it { is_expected.not_to contain_file('sshd_config').with_content(%r{^MaxSessions}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^AuthorizedKeysCommand \/path\/to\/command$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^AuthorizedKeysCommandUser asdf$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^HostbasedAuthentication no$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^PubkeyAcceptedKeyTypes ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,ssh-rsa$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^AuthenticationMethods publickey,keyboard-interactive$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^PubkeyAuthentication no$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^IgnoreUserKnownHosts no$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^IgnoreRhosts yes$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^ChrootDirectory \/chrootdir$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^ForceCommand \/force\/command --with-parameter 242$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^Match User JohnDoe\n  AllowTcpForwarding yes\Z}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^\s*Ciphers aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,arcfour,aes192-cbc,aes256-cbc$}) }
      it {
        is_expected.to contain_file('sshd_config').with_content(%r{^\s*KexAlgorithms\scurve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,
                                                                          ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,
                                                                          diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1$}x)
      }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^\s*MACs hmac-md5-etm@openssh.com,hmac-sha1-etm@openssh.com$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^\s*DenyUsers root lusers$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^\s*DenyGroups nossh wheel$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^\s*AllowUsers foo bar$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^\s*AllowGroups ssh security$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^ListenAddress 192.168.1.1\nListenAddress 2001:db8::dead:f00d$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^TCPKeepAlive yes$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^UsePrivilegeSeparation no$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^PermitTunnel no$}) }
      it { is_expected.to contain_file('sshd_config').with_content(%r{^RevokedKeys \/path\/to\/revocation_list}) }

      it {
        is_expected.to contain_file('sshd_banner').with('ensure'  => 'file',
                                                        'path'    => '/etc/sshd_banner',
                                                        'owner'   => 'root',
                                                        'group'   => 'root',
                                                        'mode'    => '0644',
                                                        'content' => 'textinbanner',
                                                        'require' => packages.map { |pkg| 'Package[' + pkg + ']' })
      }
    end

    describe 'sshd_config_chrootdirectory param' do
      ['/chrootdir/subdir', '/baby/one/more/test'].each do |value|
        context "set to valid #{value} (as #{value.class})" do
          let(:params) { { 'sshd_config_chrootdirectory' => value } }
          let(:facts) { facts }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^ChrootDirectory #{value}$}) }
        end
      end
    end

    describe 'sshd_config_forcecommand param' do
      ['/bin/command', '/bin/command -parameters', '/bin/command --parameters', '/bin/command /parameters'].each do |value|
        context "set to valid #{value} (as #{value.class})" do
          let(:facts) { facts }
          let(:params) { { 'sshd_config_forcecommand' => value } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^ForceCommand #{value}$}) }
        end
      end
    end

    describe 'sshd_config_match param' do
      # match and rules get alphabetically sorted by template, matches should be the last options in sshd_config (regex verify with= \Z)
      context 'set to valid hash containing nested arrays' do
        let(:facts) { facts }
        let(:params) do
          { sshd_config_match: {
            'User JohnDoe' => ['AllowTcpForwarding yes'],
            'Addresss 2.4.2.0' => ['X11Forwarding yes', 'PasswordAuthentication no'],
          } }
        end

        it { is_expected.to contain_file('sshd_config').with_content(%r{^Match Addresss 2.4.2.0\n  PasswordAuthentication no\n  X11Forwarding yes\nMatch User JohnDoe\n  AllowTcpForwarding yes\Z}) }
      end
    end

    describe 'sshd_config_print_last_log param' do
      ['yes', 'no'].each do |value|
        context "set to #{value}" do
          let(:facts) { facts }
          let(:params) { { sshd_config_print_last_log: value } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^PrintLastLog #{value}$}) }
        end
      end
    end

    describe 'sshd_listen_address param' do
      context 'when set to an array' do
        let(:facts) { facts }
        let(:params) { { 'sshd_listen_address' => ['192.168.1.1', '2001:db8::dead:f00d'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^ListenAddress 192.168.1.1\nListenAddress 2001:db8::dead:f00d$}) }
      end

      context 'when set to a string' do
        let(:facts) { facts }
        let(:params) { { 'sshd_listen_address' => ['192.168.1.1'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^ListenAddress 192.168.1.1$}) }
      end

      context 'when not set' do
        let(:facts) { facts }

        it { is_expected.not_to contain_file('sshd_config').with_content(%r{^\s*ListenAddress}) }
      end
    end

    describe 'sshd_loglevel param' do
      ['QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE'].each do |supported_val|
        context "when set to #{supported_val}" do
          let(:facts) { facts }
          let(:params) { { 'sshd_config_loglevel' => supported_val } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^LogLevel #{supported_val}$}) }
        end
      end
    end

    describe 'with sshd_kerberos_authentication' do
      ['yes', 'no'].each do |value|
        context "set to #{value}" do
          let(:facts) { facts }
          let(:params) { { 'sshd_kerberos_authentication' => value } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^KerberosAuthentication #{value}$}) }
        end
      end
    end

    context 'when ssh_config_template has a nonstandard value' do
      context 'and that value is valid' do
        let(:facts) { facts }
        let(:params) { { 'ssh_config_template' => 'ssh/sshd_config.erb' } }

        it 'lays down the ssh_config file from the specified template' do
          is_expected.to contain_file('ssh_config').with_content(%r{OpenBSD: sshd_config})
        end
      end
    end

    context 'when sshd_config_template has a nonstandard value' do
      context 'and that value is valid' do
        let(:facts) { facts }
        let(:params) { { 'sshd_config_template' => 'ssh/ssh_config.erb' } }

        it 'lays down the sshd_config file from the specified template' do
          is_expected.to contain_file('sshd_config').with_content(%r{OpenBSD: ssh_config})
        end
      end
    end

    context 'with manage_root_ssh_config set to true on valid osfamily' do
      let(:facts) { facts }
      let(:params) { { manage_root_ssh_config: true } }

      it { is_expected.to compile.with_all_deps }
      it { is_expected.to contain_class('ssh') }
      it {
        is_expected.to contain_file('root_ssh_dir').with('ensure' => 'directory',
                                                         'path'    => '/root/.ssh',
                                                         'owner'   => 'root',
                                                         'group'   => 'root',
                                                         'mode'    => '0700')
      }
      it {
        is_expected.to contain_file('root_ssh_config').with('ensure' => 'file',
                                                            'path'   => '/root/.ssh/config',
                                                            'owner'  => 'root',
                                                            'group'  => 'root',
                                                            'mode'   => '0600')
      }
    end

    context 'with manage_root_ssh_config set to false on valid osfamily' do
      let(:facts) { facts }
      let(:params) { { manage_root_ssh_config: false } }

      it { is_expected.to compile.with_all_deps }
      it { is_expected.to contain_class('ssh') }
      it { is_expected.not_to contain_class('common') }
      it { is_expected.not_to contain_file('root_ssh_dir') }
      it { is_expected.not_to contain_file('root_ssh_config') }
    end

    describe 'with ssh_config_hash_known_hosts param' do
      ['yes', 'no'].each do |value|
        context "set to #{value}" do
          let(:facts) { facts }
          let(:params) { { ssh_config_hash_known_hosts: value } }

          it { is_expected.to contain_file('ssh_config').with_content(%r{^\s*HashKnownHosts #{value}$}) }
        end
      end
    end

    describe 'with sshd_config_permitemptypasswords' do
      ['yes', 'no'].each do |value|
        context "set to #{value}" do
          let(:facts) { facts }
          let(:params) { { 'sshd_config_permitemptypasswords' => value } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^PermitEmptyPasswords #{value}$}) }
        end
      end
    end

    describe 'with sshd_config_permituserenvironment' do
      ['yes', 'no'].each do |value|
        context "set to #{value}" do
          let(:facts) { facts }
          let(:params) { { 'sshd_config_permituserenvironment' => value } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^PermitUserEnvironment #{value}$}) }
        end
      end
    end

    describe 'sshd_config_compression param' do
      ['yes', 'no', 'delayed'].each do |value|
        context "set to #{value}" do
          let(:facts) { facts }
          let(:params) { { sshd_config_compression: value } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^Compression #{value}$}) }
        end
      end
    end

    describe 'sshd_config_port param' do
      context 'when set to an array' do
        let(:facts) { facts }
        let(:params) { { 'sshd_config_port' => [22_222, 22_223] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^Port 22222\nPort 22223$}) }
      end

      context 'when set to a string' do
        let(:facts) { facts }
        let(:params) { { 'sshd_config_port' => [22_222] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^Port 22222$}) }
      end

      context 'when set to an integer' do
        let(:facts) { facts }
        let(:params) { { 'sshd_config_port' => [22_222] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^Port 22222$}) }
      end
    end

    describe 'sshd_config_permittunnel param' do
      ['yes', 'point-to-point', 'ethernet', 'no'].each do |value|
        context "set to #{value}" do
          let(:facts) { facts }
          let(:params) { { sshd_config_permittunnel: value } }

          if value == 'unset'
            it { is_expected.to contain_file('sshd_config').without_content(%r{^\s*PermitTunnel}) }
          else
            it { is_expected.to contain_file('sshd_config').with_content(%r{^PermitTunnel #{value}$}) }
          end
        end
      end
    end

    describe 'sshd_config_key_revocation_list param' do
      context 'set to /path/to' do
        let(:facts) { facts }
        let(:params) { { sshd_config_key_revocation_list: '/path/to' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^RevokedKeys /path/to$}) }
      end

      context 'not set' do
        let(:facts) { facts }

        it { is_expected.to contain_file('sshd_config').without_content(%r{^\s*RevokedKeys}) }
      end
    end

    describe 'sshd_config_hostcertificate param' do
      context 'unset value' do
        let(:facts) { facts }

        it { is_expected.to contain_file('sshd_config').without_content(%r{^\s*HostCertificate}) }
      end

      context 'with a certificate' do
        let(:facts) { facts }
        let(:params) { { sshd_config_hostcertificate: ['/etc/ssh/ssh_host_key-cert.pub'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^HostCertificate \/etc\/ssh\/ssh_host_key-cert\.pub}) }
      end

      context 'with multiple certs' do
        let(:facts) { facts }
        let(:params) { { sshd_config_hostcertificate: ['/etc/ssh/ssh_host_key-cert.pub', '/etc/ssh/ssh_host_key-cert2.pub'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^HostCertificate \/etc\/ssh\/ssh_host_key-cert\.pub\nHostCertificate \/etc\/ssh\/ssh_host_key-cert2\.pub}) }
      end
    end

    context 'with sshd_config_authorized_principals_file param' do
      context 'set to .ssh/authorized_principals' do
        let(:facts) { facts }
        let(:params) { { sshd_config_authorized_principals_file: '.ssh/authorized_principals' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^AuthorizedPrincipalsFile \.ssh\/authorized_principals}) }
      end

      context 'not set' do
        let(:facts) { facts }

        it { is_expected.to contain_file('sshd_config').without_content(%r{^\s*AuthorizedPrincipalsFile}) }
      end
    end

    describe 'sshd_config_trustedusercakeys param' do
      context 'set to /etc/ssh/authorized_users_ca.pub' do
        let(:facts) { facts }
        let(:params) { { sshd_config_trustedusercakeys: '/etc/ssh/authorized_users_ca.pub' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^TrustedUserCAKeys /etc/ssh/authorized_users_ca.pub}) }
      end
    end

    describe 'with sshd_config_allowagentforwarding' do
      ['yes', 'no'].each do |value|
        context "set to #{value}" do
          let(:facts) { facts }
          let(:params) { { 'sshd_config_allowagentforwarding' => value } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^AllowAgentForwarding #{value}$}) }
        end
      end
    end

    context 'with sshd_banner_content set and with default value on sshd_config_banner on valid osfamily' do
      let(:facts) { facts }
      let(:params) { { sshd_banner_content: 'textinbanner' } }

      it 'fails' do
        expect {
          is_expected.to contain_class('ssh')
        }.to raise_error(Puppet::Error, %r{ssh::sshd_config_banner must be set to be able to use sshd_banner_content\.})
      end
    end

    context 'with manage_firewall set to true on valid osfamily' do
      let(:facts) { facts }
      let(:params) { { manage_firewall: true } }

      it { is_expected.to compile.with_all_deps }

      it { is_expected.to contain_class('ssh') }

      it { is_expected.not_to contain_class('common') }

      it {
        is_expected.to contain_firewall('22 open port 22 for SSH').with('action' => 'accept',
                                                                        'dport'  => '22',
                                                                        'proto'  => 'tcp')
      }
    end

    context 'with config_entries defined on valid osfamily' do
      let(:facts) { facts }
      let(:params) do
        {
          config_entries: {
            'root' => {
              'owner' => 'root',
              'group' => 'root',
              'path'  => '/root/.ssh/config',
              'host'  => 'test_host1',
            },
            'user' => {
              'owner' => 'user',
              'group' => 'group',
              'path'  => '/home/user/.ssh/config',
              'host'  => 'test_host2',
              'order' => '242',
              'lines' => ['ForwardX11 no', 'StrictHostKeyChecking no'],
            },
          },
        }
      end

      it { is_expected.to compile.with_all_deps }
      it { is_expected.to have_ssh__config_entry_resource_count(2) }
      it do
        is_expected.to contain_ssh__config_entry('root').with('owner' => 'root',
                                                              'group' => 'root',
                                                              'path'  => '/root/.ssh/config',
                                                              'host'  => 'test_host1')
      end
      it do
        is_expected.to contain_ssh__config_entry('user').with('owner' => 'user',
                                                              'group' => 'group',
                                                              'path'  => '/home/user/.ssh/config',
                                                              'host'  => 'test_host2',
                                                              'order' => '242',
                                                              'lines' => ['ForwardX11 no', 'StrictHostKeyChecking no'])
      end
    end

    describe 'with hiera providing data from multiple levels' do
      let(:facts) do
        facts.merge(fqdn: 'hieramerge.example.com',
                    specific: 'test_hiera_merge')
      end

      context 'with defaults for all parameters' do
        it { is_expected.to have_ssh__config_entry_resource_count(1) }
        it { is_expected.to contain_ssh__config_entry('user_from_fqdn') }
      end

      context 'with hiera_merge set to valid <true>' do
        let(:params) { { hiera_merge: true } }

        it { is_expected.to have_ssh__config_entry_resource_count(2) }
        it { is_expected.to contain_ssh__config_entry('user_from_fqdn') }
        it { is_expected.to contain_ssh__config_entry('user_from_fact') }
      end
    end

    context 'with keys defined on valid osfamily' do
      let(:facts) { facts }
      let(:params) do
        { keys: {
          'root_for_userX' => {
            'ensure' => 'present',
            'user'   => 'root',
            'type'   => 'dsa',
            'key'    => 'AAAA==',
          },
          'apache_hup' => {
            'ensure' => 'present',
            'user'    => 'apachehup',
            'type'    => 'dsa',
            'key'     => 'AAAA==',
            'options' => 'command="/sbin/service httpd restart"',
          },
          'root_for_userY' => {
            'ensure' => 'absent',
            'user' => 'root',
          },
        } }
      end

      it { is_expected.to compile.with_all_deps }

      it {
        is_expected.to contain_ssh_authorized_key('root_for_userX').with('ensure' => 'present',
                                                                         'user'   => 'root',
                                                                         'type'   => 'dsa',
                                                                         'key'    => 'AAAA==')
      }

      it {
        is_expected.to contain_ssh_authorized_key('apache_hup').with('ensure' => 'present',
                                                                     'user'    => 'apachehup',
                                                                     'type'    => 'dsa',
                                                                     'key'     => 'AAAA==',
                                                                     'options' => 'command="/sbin/service httpd restart"')
      }

      it {
        is_expected.to contain_ssh_authorized_key('root_for_userY').with('ensure' => 'absent',
                                                                         'user' => 'root')
      }
    end

    context 'with keys specified as not of type hash' do
      let(:facts) { facts }
      let(:params) { { keys: ['not', 'a', 'hash'] } }

      it 'fails' do
        expect {
          is_expected.to contain_class('ssh')
        }.to raise_error(Puppet::Error)
      end
    end

    describe 'with hiera_merge parameter specified' do
      context 'as a non-boolean or non-string' do
        let(:facts) { facts.merge(fqdn: 'hieramerge.example.com') }
        let(:params) { { hiera_merge: ['not_a_boolean', 'or_a_string'] } }

        it 'fails' do
          expect {
            is_expected.to contain_class('ssh')
          }.to raise_error(Puppet::Error)
        end
      end

      context 'as true with hiera data getting collected' do
        let(:facts) { facts.merge(fqdn: 'hieramerge.example.com') }
        let(:params) { { hiera_merge: true } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('ssh') }
        it { is_expected.to contain_file('sshd_config').with_content(%r{^\s*DenyUsers denyuser_from_fqdn}) }
        it { is_expected.to contain_file('sshd_config').with_content(%r{^\s*DenyGroups denygroup_from_fqdn}) }
        it { is_expected.to contain_file('sshd_config').with_content(%r{^\s*AllowUsers allowuser_from_fqdn}) }
        it { is_expected.to contain_file('sshd_config').with_content(%r{^\s*AllowGroups allowgroup_from_fqdn}) }
      end

      context 'as true with with hiera data getting merged through levels' do
        let(:facts) do
          facts.merge(
            fqdn: 'hieramerge.example.com',
            specific: 'test_hiera_merge',
          )
        end
        let(:params) { { hiera_merge: true } }

        it { is_expected.to compile.with_all_deps }

        it { is_expected.to contain_class('ssh') }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^\s*DenyUsers denyuser_from_fqdn denyuser_from_fact}) }
        it { is_expected.to contain_file('sshd_config').with_content(%r{^\s*DenyGroups denygroup_from_fqdn denygroup_from_fact}) }
        it { is_expected.to contain_file('sshd_config').with_content(%r{^\s*AllowUsers allowuser_from_fqdn allowuser_from_fact}) }
        it { is_expected.to contain_file('sshd_config').with_content(%r{^\s*AllowGroups allowgroup_from_fqdn allowgroup_from_fact}) }
      end

      context 'as true with no hiera data provided' do
        let(:facts) { facts }
        let(:params) { { hiera_merge: true } }

        it { is_expected.to compile.with_all_deps }

        it { is_expected.to contain_class('ssh') }

        it { is_expected.to contain_file('sshd_config').without_content(%r{^\s*DenyUsers}) }
        it { is_expected.to contain_file('sshd_config').without_content(%r{^\s*DenyGroups}) }
        it { is_expected.to contain_file('sshd_config').without_content(%r{^\s*AllowUsers}) }
        it { is_expected.to contain_file('sshd_config').without_content(%r{^\s*AllowGroups}) }
      end

      context 'as false' do
        let(:facts) { facts }
        let(:params) { { hiera_merge: false } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('ssh') }
      end
    end

    describe 'with ssh_package_adminfile parameter specified' do
      context 'as a valid path' do
        let(:facts) { facts }
        let(:params) { { ssh_package_adminfile: '/var/tmp/admin' } }

        packages.each do |pkg|
          it {
            is_expected.to contain_package(pkg).with('ensure' => 'installed',
                                                     'source'    => default_ssh_package_source,
                                                     'adminfile' => '/var/tmp/admin')
          }
        end
      end
    end

    describe 'with sshd_config_xauth_location parameter specified' do
      context 'as a valid path' do
        let(:facts) { facts }
        let(:params) { { sshd_config_xauth_location: '/opt/ssh/bin/xauth' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^XAuthLocation \/opt\/ssh\/bin\/xauth$}) }
      end
    end

    describe 'with ssh_package_source parameter specified' do
      let(:facts) { facts }

      context 'as a valid path' do
        let(:params) { { ssh_package_source: '/mnt/packages' } }

        packages.each do |pkg|
          it {
            is_expected.to contain_package(pkg).with('ensure' => 'installed',
                                                     'source'    => '/mnt/packages',
                                                     'adminfile' => nil)
          }
        end
      end
    end

    describe 'with parameter ssh_config_forward_x11_trusted' do
      ['yes', 'no'].each do |value|
        context "specified as #{value}" do
          let(:facts) { facts }
          let(:params) { { ssh_config_forward_x11_trusted: value } }

          it { is_expected.to contain_file('ssh_config').with_content(%r{^\s*ForwardX11Trusted #{value}$}) }
        end
      end
      if facts[:os]['family'] == 'Solaris'
        context 'not specified' do
          let(:facts) { facts }

          it { is_expected.not_to contain_file('ssh_config').with_content(%r{^\s*ForwardX11Trusted}) }
        end
      end
    end

    describe 'with parameter ssh_gssapidelegatecredentials' do
      ['yes', 'no'].each do |value|
        context "specified as #{value}" do
          let(:facts) { facts }
          let(:params) { { ssh_gssapidelegatecredentials: value } }

          it { is_expected.to contain_file('ssh_config').with_content(%r{^GSSAPIDelegateCredentials #{value}$}) }
        end
      end
    end

    describe 'with parameter ssh_gssapiauthentication' do
      ['yes', 'no'].each do |value|
        context "specified as valid #{value} (as #{value.class})" do
          let(:facts) { facts }
          let(:params) { { ssh_gssapiauthentication: value } }

          it { is_expected.to contain_file('ssh_config').with_content(%r{^\s*GSSAPIAuthentication #{value}$}) }
        end
      end
    end

    describe 'with parameter ssh_hostbasedauthentication' do
      ['yes', 'no'].each do |value|
        context "specified as valid #{value} (as #{value.class})" do
          let(:facts) { facts }
          let(:params) { { ssh_hostbasedauthentication: value } }

          it { is_expected.to contain_file('ssh_config').with_content(%r{^\s*HostbasedAuthentication #{value}$}) }
        end
      end
    end

    describe 'with parameter ssh_strict_host_key_checking' do
      ['yes', 'no', 'ask'].each do |value|
        context "specified as valid #{value} (as #{value.class})" do
          let(:facts) { facts }
          let(:params) { { ssh_strict_host_key_checking: value } }

          it { is_expected.to contain_file('ssh_config').with_content(%r{^\s*StrictHostKeyChecking #{value}$}) }
        end
      end
    end

    describe 'with parameter ssh_enable_ssh_keysign' do
      ['yes', 'no'].each do |value|
        context "specified as valid #{value} (as #{value.class})" do
          let(:facts) { facts }
          let(:params) { { ssh_enable_ssh_keysign: value } }

          it { is_expected.to contain_file('ssh_config').with_content(%r{^\s*EnableSSHKeysign #{value}$}) }
        end
      end
    end

    describe 'with parameter sshd_gssapiauthentication' do
      ['yes', 'no'].each do |value|
        context "specified as valid #{value} (as #{value.class})" do
          let(:facts) { facts }
          let(:params) { { sshd_gssapiauthentication: value } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^GSSAPIAuthentication #{value}$}) }
        end
      end
    end

    describe 'with parameter sshd_gssapikeyexchange' do
      ['yes', 'no'].each do |value|
        context "specified as #{value}" do
          let(:facts) { facts }
          let(:params) { { sshd_gssapikeyexchange: value } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^GSSAPIKeyExchange #{value}$}) }
        end
      end
      if facts[:os]['family'] != 'Solaris'
        context 'not specified' do
          let(:facts) { facts }

          it { is_expected.not_to contain_file('sshd_config').with_content(%r{^\s*GSSAPIKeyExchange}) }
        end
      end
    end

    describe 'with parameter sshd_pamauthenticationviakbdint' do
      ['yes', 'no'].each do |value|
        context "specified as #{value}" do
          let(:facts) { facts }
          let(:params) { { sshd_pamauthenticationviakbdint: value } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^PAMAuthenticationViaKBDInt #{value}$}) }
        end
      end

      if facts[:os]['family'] != 'Solaris'
        context 'not specified' do
          let(:facts) { facts }

          it { is_expected.not_to contain_file('sshd_config').with_content(%r{^\s*PAMAuthenticationViaKBDInt}) }
        end
      end
    end

    describe 'with parameter sshd_gssapicleanupcredentials' do
      ['yes', 'no'].each do |value|
        context "specified as #{value}" do
          let(:facts) { facts }
          let(:params) { { sshd_gssapicleanupcredentials: value } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^GSSAPICleanupCredentials #{value}$}) }
        end
      end

      if facts[:os]['family'] == 'Solaris'
        context 'not specified' do
          let(:facts) { facts }

          it { is_expected.not_to contain_file('sshd_config').with_content(%r{^\s*GSSAPICleanupCredentials}) }
        end
      end
    end

    describe 'with parameter ssh_sendenv specified' do
      context 'as true' do
        let(:facts) { facts }
        let(:params) { { ssh_sendenv: true } }

        it { is_expected.to contain_file('ssh_config').with_content(%r{^\s*SendEnv}) }
      end

      context 'as false' do
        let(:facts) { facts }
        let(:params) { { ssh_sendenv: false } }

        it { is_expected.not_to contain_file('ssh_config').with_content(%r{^\s*SendEnv}) }
      end
    end

    describe 'with paramter sshd_config_maxauthtries specified' do
      context 'as a valid integer' do
        let(:facts) { facts }
        let(:params) { { sshd_config_maxauthtries: 6 } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^MaxAuthTries 6$}) }
      end
    end

    describe 'with parameter sshd_config_maxstartups specified' do
      ['10', '10:30:100'].each do |value|
        context "as a valid string - #{value}" do
          let(:facts) { facts }
          let(:params) { { sshd_config_maxstartups: value } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^MaxStartups #{value}$}) }
        end
      end
    end

    describe 'parameter sshd_config_maxsessions' do
      context 'as a valid integer' do
        let(:facts) { facts }
        let(:params) { { sshd_config_maxsessions: 10 } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^MaxSessions 10$}) }
      end

      context 'without parameter' do
        let(:facts) { facts }

        it { is_expected.to contain_file('sshd_config').without_content(%r{^\s*MaxSessions}) }
      end
    end

    describe 'with parameter sshd_acceptenv specified' do
      context 'as true' do
        let(:facts) { facts }
        let(:params) { { sshd_acceptenv: true } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^\s*AcceptEnv}) }
      end

      context 'as false' do
        let(:facts) { facts }
        let(:params) { { sshd_acceptenv: false } }

        it { is_expected.not_to contain_file('sshd_config').with_content(%r{^\s*AcceptEnv}) }
      end
    end

    describe 'with parameter service_hasstatus' do
      [true, false].each do |value|
        context "specified as #{value}" do
          let(:facts) { facts }
          let(:params) { { service_hasstatus: value } }

          it {
            is_expected.to contain_service('sshd_service').with('ensure' => 'running',
                                                                'name'       => service_name,
                                                                'enable'     => 'true',
                                                                'hasrestart' => 'true',
                                                                'hasstatus'  => value,
                                                                'subscribe'  => 'File[sshd_config]')
          }
        end
      end
    end

    describe 'with parameter ssh_config_global_known_hosts_file' do
      context 'specified as a valid path' do
        let(:facts) { facts }
        let(:params) { { ssh_config_global_known_hosts_file: '/valid/path' } }

        it {
          is_expected.to contain_file('ssh_known_hosts').with('ensure' => 'file',
                                                              'path'   => '/valid/path',
                                                              'owner'  => 'root',
                                                              'group'  => 'root',
                                                              'mode'   => '0644',
                                                              'require' => packages.map { |pkg| 'Package[' + pkg + ']' })
        }

        it { is_expected.to contain_file('ssh_config').with_content(%r{^\s*GlobalKnownHostsFile \/valid\/path$}) }
      end
    end

    describe 'with parameter ssh_config_global_known_hosts_list' do
      context 'when set to an array of valid absolute paths' do
        let(:facts) { facts }
        let(:params) { { 'ssh_config_global_known_hosts_list' => ['/valid/path1', '/valid/path2'] } }

        it { is_expected.to contain_file('ssh_config').with_content(%r{^\s*GlobalKnownHostsFile.*\/valid\/path1 \/valid\/path2$}) }
      end
    end

    describe 'with parameter ssh_config_user_known_hosts_file' do
      context 'when set to an array of paths' do
        let(:facts) { facts }
        let(:params) { { 'ssh_config_user_known_hosts_file' => ['valid/path1', '/valid/path2'] } }

        it { is_expected.to contain_file('ssh_config').with_content(%r{^\s*UserKnownHostsFile valid\/path1 \/valid\/path2$}) }
      end
    end

    describe 'with parameter ssh_config_global_known_hosts_owner' do
      context 'specified as a valid string' do
        let(:facts) { facts }
        let(:params) { { ssh_config_global_known_hosts_owner: 'gh' } }

        it {
          is_expected.to contain_file('ssh_known_hosts').with('ensure' => 'file',
                                                              'path'   => '/etc/ssh/ssh_known_hosts',
                                                              'owner'  => 'gh',
                                                              'group'  => 'root',
                                                              'mode'   => '0644',
                                                              'require' => packages.map { |pkg| 'Package[' + pkg + ']' })
        }
      end
    end

    describe 'with parameter ssh_config_global_known_hosts_group' do
      context 'specified as a valid string' do
        let(:facts) { facts }
        let(:params) { { ssh_config_global_known_hosts_group: 'gh' } }

        it {
          is_expected.to contain_file('ssh_known_hosts').with('ensure' => 'file',
                                                              'path'   => '/etc/ssh/ssh_known_hosts',
                                                              'owner'  => 'root',
                                                              'group'  => 'gh',
                                                              'mode'   => '0644',
                                                              'require' => packages.map { |pkg| 'Package[' + pkg + ']' })
        }
      end
    end

    describe 'with parameter ssh_config_global_known_hosts_mode' do
      context 'specified as a valid mode' do
        let(:facts) { facts }
        let(:params) { { ssh_config_global_known_hosts_mode: '0666' } }

        it {
          is_expected.to contain_file('ssh_known_hosts').with('ensure' => 'file',
                                                              'path'   => '/etc/ssh/ssh_known_hosts',
                                                              'owner'  => 'root',
                                                              'group'  => 'root',
                                                              'mode'   => '0666',
                                                              'require' => packages.map { |pkg| 'Package[' + pkg + ']' })
        }
      end

      context 'as true' do
        let(:facts) { facts }
        let(:params) { { ssh_key_import: true } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('ssh') }
        it {
          is_expected.to contain_file('ssh_known_hosts').with('ensure' => 'file',
                                                              'path'    => '/etc/ssh/ssh_known_hosts',
                                                              'owner'   => 'root',
                                                              'group'   => 'root',
                                                              'mode'    => '0644',
                                                              'require' => packages.map { |pkg| 'Package[' + pkg + ']' })
        }
      end

      context 'as false' do
        let(:facts) { facts }
        let(:params) { { ssh_key_import: false } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('ssh') }
      end
    end

    describe 'with parameter sshd_hostbasedauthentication' do
      ['yes', 'no'].each do |value|
        context "specified as valid #{value} (as #{value.class})" do
          let(:facts) { facts }
          let(:params) { { sshd_hostbasedauthentication: value } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^HostbasedAuthentication #{value}$}) }
        end
      end
    end

    describe 'with parameter sshd_pubkeyauthentication' do
      ['yes', 'no'].each do |value|
        context "specified as valid #{value} (as #{value.class})" do
          let(:facts) { facts }
          let(:params) { { sshd_pubkeyauthentication: value } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^PubkeyAuthentication #{value}$}) }
        end
      end
    end

    describe 'with parameter sshd_ignoreuserknownhosts' do
      ['yes', 'no'].each do |value|
        context "specified as valid #{value} (as #{value.class})" do
          let(:facts) { facts }
          let(:params) { { sshd_ignoreuserknownhosts: value } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^IgnoreUserKnownHosts #{value}$}) }
        end
      end
    end

    describe 'with parameter sshd_ignorerhosts' do
      ['yes', 'no'].each do |value|
        context "specified as valid #{value} (as #{value.class})" do
          let(:facts) { facts }
          let(:params) { { sshd_ignorerhosts: value } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^IgnoreRhosts #{value}$}) }
        end
      end
    end

    describe 'with parameter manage_service' do
      context 'specified as true' do
        let(:facts) { facts }
        let(:params) { { manage_service: true } }

        it { is_expected.to contain_service('sshd_service') }
      end

      context 'specified as false' do
        let(:facts) { facts }
        let(:params) { { manage_service: false } }

        it { is_expected.not_to contain_service('sshd_service') }
      end
    end

    describe 'sshd_config_tcp_keepalive param' do
      ['yes', 'no'].each do |value|
        context "set to #{value}" do
          let(:facts) { facts }
          let(:params) { { sshd_config_tcp_keepalive: value } }

          if value == 'unset'
            it { is_expected.to contain_file('sshd_config').without_content(%r{^\s*TCPKeepAlive}) }
          else
            it { is_expected.to contain_file('sshd_config').with_content(%r{^TCPKeepAlive #{value}$}) }
          end
        end
      end
    end

    describe 'sshd_config_use_privilege_separation param' do
      ['yes', 'no', 'sandbox'].each do |value|
        context "set to #{value}" do
          let(:facts) { facts }
          let(:params) { { sshd_config_use_privilege_separation: value } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^UsePrivilegeSeparation #{value}$}) }
        end
      end
    end

    if facts[:os]['family'] != 'Solaris'
      describe 'with parameter sshd_addressfamily' do
        ['any', 'inet', 'inet6'].each do |value|
          context "set to a valid entry of #{value}" do
            let(:facts) { facts }
            let(:params) { { sshd_addressfamily: value } }

            it { is_expected.to contain_file('sshd_config').with_content(%r{^AddressFamily #{value}$}) }
          end
        end
      end
    end

    describe 'with parameter ssh_config_use_roaming' do
      ['yes', 'no', 'unset'].each do |value|
        context "set to valid value #{value}" do
          let(:facts) { facts }
          let(:params) { { ssh_config_use_roaming: value } }

          if value == 'unset'
            it { is_expected.to contain_file('ssh_config').without_content(%r{^\s*UseRoaming}) }
          else
            it { is_expected.to contain_file('ssh_config').with_content(%r{^\s*UseRoaming #{value}$}) }
          end
        end
      end
    end
  end
end
