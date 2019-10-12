# == Define: ssh::config_entry
#
# Manage an entry in ~/.ssh/config for a particular user.  Lines model the lines
# in each Host block.
define ssh::config_entry (
  String                   $owner,
  String                   $group,
  String                   $path,
  String                   $host,
  Variant[String, Integer] $order  = '10',
  String                   $ensure = 'present',
  Array[String]            $lines  = [],
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
