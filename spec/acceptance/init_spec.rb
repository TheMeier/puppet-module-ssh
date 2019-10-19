require 'spec_helper_acceptance'

describe 'ssh class' do
  describe 'basic usage' do
    let(:pp) do
      <<-MANIFEST
        class { 'ssh':
          manage_service => false,
        }
      MANIFEST
    end

    it 'behaves idempotently' do
      idempotent_apply(pp)
    end

    describe file('/etc/ssh/sshd_config') do
      it { is_expected.to be_file }
      it { is_expected.to contain 'This file is being maintained by Puppet.' }
    end
  end
end
