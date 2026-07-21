# frozen_string_literal: true

require 'spec_helper'
require 'awesome_print'

# rubocop:disable RSpec/SubjectStub
describe Puppet::Type.type(:local_security_policy).provider(:policy) do
  include PuppetlabsSpec::Fixtures

  subject { described_class }

  before(:each) do
    allow(Puppet::Util).to receive(:which).with('secedit').and_return('c:\\tools\\secedit')

    infout = StringIO.new
    sdbout = StringIO.new
    allow(described_class).to receive(:read_policy_settings).and_return(inf_data)
    allow(Tempfile).to receive(:new).with('infimport').and_return(infout)
    allow(Tempfile).to receive(:new).with('sdbimport').and_return(sdbout)
    allow(File).to receive(:file?).with(secdata).and_return(true)
    # the below mock seems to be required or rspec complains
    allow(File).to receive(:file?).with(%r{facter|lsb_release}).and_return(true)
    allow(subject).to receive_messages(read_policy_settings: inf_data, temp_file: secdata)
    allow(subject).to receive(:secedit).with(['/configure', '/db', 'sdbout', '/cfg', 'infout', '/quiet']).and_return(true)
    allow(subject).to receive(:secedit).with(['/export', '/cfg', secdata, '/quiet']).and_return(true)
  end

  let(:facts) { os_facts }

  let(:security_policy) do
    SecurityPolicy.new
  end

  let(:inf_data) do
    inffile_content = File.read(secdata).encode('utf-8', universal_newline: true).delete("\xEF\xBB\xBF")
    PuppetX::IniFile.new(content: inffile_content)
  end
  # mock up the data which was gathered on a real windows system
  let(:secdata) do
    my_fixture(File.join('..', 'secedit.inf'))
  end

  let(:resource) do
    Puppet::Type.type(:local_security_policy).new(
      name: 'Network access: Let Everyone permissions apply to anonymous users',
      ensure: 'present',
      policy_setting: 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
      policy_type: 'Registry Values',
      policy_value: '0',
    )
  end
  let(:provider) do
    described_class.new(resource)
  end

  it 'creates instances without error' do
    instances = described_class.instances
    expect(instances.class).to eq(Array)
    expect(instances.count).to be >= 114
  end

  # if you get this error, your are missing a entry in the lsp_mapping under puppet_x/security_policy
  # either its a type, case, or missing entry
  it 'lsp_mapping contains all the entries in secdata file' do
    inffile = subject.read_policy_settings
    missing_policies = {}

    inffile.sections.each do |section|
      next if section == 'Unicode'
      next if section == 'Version'

      inffile[section].each do |name, value|
        SecurityPolicy.find_mapping_from_policy_name(name)
      rescue KeyError => e
        puts e.message # rubocop:disable RSpec/Output -- diagnostic output for maintainers when this test fails, see comment above
        if value && section == 'Registry Values'
          reg_type = value.split(',').first
          missing_policies[name] = { name: name, policy_type: section, reg_type: reg_type }
        else
          missing_policies[name] = { name: name, policy_type: section }
        end
      end
    end
    ap missing_policies # rubocop:disable RSpec/Output -- diagnostic output for maintainers when this test fails, see comment above

    expect(missing_policies.count).to eq(0), 'Missing policy, check the lsp mapping'
  end

  it 'ensure instances works', skip: 'Puppet::Type.type(...).instances goes through provider suitability confinement (confine operatingsystem: :windows), so it returns 0 instances on this non-Windows test host' do
    instances = Puppet::Type.type(:local_security_policy).instances
    expect(instances.count).to be > 1
  end

  describe 'write output' do
    let(:resource) do
      Puppet::Type.type(:local_security_policy).new(
        name: 'Recovery console: Allow automatic administrative logon',
        ensure: 'present',
        policy_setting: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel',
        policy_type: 'Registry Values',
        policy_value: '0',
      )
    end

    it 'writes out the file correctly' do
      provider.create
    end
  end

  describe 'resource is removed' do
    let(:resource) do
      Puppet::Type.type(:local_security_policy).new(
        name: 'Network access: Let Everyone permissions apply to anonymous users',
        ensure: 'absent',
        policy_setting: 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
        policy_type: 'Registry Values',
        policy_value: '0',
      )
    end

    it 'exists? is true' do
      expect(provider.exists?).to be(false)
      # until we can implement the destroy functionality this test is useless
      # expect(provider).to receive(:destroy).exactly(1).times
    end
  end

  describe 'resource is present' do
    let(:secdata) do
      my_fixture(File.join('..', 'short_secedit.inf'))
    end
    let(:resource) do
      Puppet::Type.type(:local_security_policy).new(
        name: 'Recovery console: Allow automatic administrative logon',
        ensure: 'present',
        policy_setting: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel',
        policy_type: 'Registry Values',
        policy_value: '0',
      )
    end

    it 'exists? is true' do
      expect(provider).to receive(:create).exactly(0).times
    end
  end

  describe 'resource is absent' do
    let(:resource) do
      Puppet::Type.type(:local_security_policy).new(
        name: 'Recovery console: Allow automatic administrative logon',
        ensure: 'present',
        policy_setting: '1MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel',
        policy_type: 'Registry Values',
        policy_value: '76',
      )
    end

    it 'exists? is false' do
      expect(provider.exists?).to be(false)
      allow(provider).to receive(:create).once
    end
  end

  it 'is an instance of Puppet::Type::Local_security_policy::ProviderPolicy' do
    expect(provider).to be_an_instance_of Puppet::Type::Local_security_policy::ProviderPolicy
  end
end
# rubocop:enable RSpec/SubjectStub
