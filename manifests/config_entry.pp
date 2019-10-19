# @summary Create config entries in a users' ~/.ssh/config
#
# @example Basic usage
#   ssh::config_entry { 'jenkins github.com':
#    host  => 'github.com',
#    lines => ["  IdentityFile /home/jenkins/.ssh/jenkins-gihub.key"],
#    order => '20',
#   }
#
# @ see https://man.openbsd.org/ssh_config
#
# @param owner
# @param group
# @param path
# @param host
# @param order
# @param ensure
# @param lines
define ssh::config_entry (
  String                   $group,
  String                   $host,
  String                   $owner,
  String                   $path,
  String                   $ensure = 'present',
  Array[String]            $lines  = [],
  Variant[String, Integer] $order  = '10',
) {

  # All lines including the host line.  This will be joined with "\n  " for
  # indentation.
  $entry = concat(["Host ${host}"], $lines)
  $content = join($entry, "\n")

  if ! defined(Concat[$path]) {
    concat { $path:
      ensure         => present,
      owner          => $owner,
      group          => $group,
      mode           => '0644',
      ensure_newline => true,
    }
  }

  concat::fragment { "${path} Host ${host}":
    target  => $path,
    content => $content,
    order   => $order,
    tag     => "${owner}_ssh_config",
  }
}
