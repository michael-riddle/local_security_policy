# frozen_string_literal: true

require 'spec_helper'

describe Puppet::Type.type(:local_security_policy) do
  [:name].each do |param|
    it "has a #{param} parameter" do
      expect(Puppet::Type.type(:local_security_policy).attrtype(param)).to eq(:param)
    end
  end

  [:policy_type, :ensure, :ensure, :policy_setting, :policy_value].each do |param|
    it "has a #{param} property" do
      expect(Puppet::Type.type(:local_security_policy).attrtype(param)).to eq(:property)
    end
  end

  describe 'test validation' do
    it 'creates a registry value' do
      resource = Puppet::Type.type(:local_security_policy).new(
        name: 'Network access: Let Everyone permissions apply to anonymous users',
        ensure: 'present',
        policy_setting: 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
        policy_type: 'Registry Values',
        policy_value: '0',
      )
      expect(resource[:policy_value]).to eq('4,0')
    end

    it 'creates a domain controller registry value and derives its setting from the mapping' do
      resource = Puppet::Type.type(:local_security_policy).new(
        name: 'Domain controller: LDAP server signing requirements',
        ensure: 'present',
        policy_value: '2',
      )
      expect(resource[:policy_value]).to eq('4,2')
      expect(resource[:policy_setting]).to eq('MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity')
    end

    it 'creates a domain controller string registry value' do
      resource = Puppet::Type.type(:local_security_policy).new(
        name: 'Domain controller: Allow vulnerable Netlogon secure channel connections',
        ensure: 'present',
        policy_value: 'O:BAG:BAD:(A;;RC;;;BA)',
      )
      expect(resource[:policy_value]).to eq('1,O:BAG:BAD:(A;;RC;;;BA)')
      expect(resource[:policy_setting]).to eq('MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList')
    end

    it 'creates an event audit value' do
      resource = Puppet::Type.type(:local_security_policy).new(
        name: 'Audit account logon events',
        ensure: 'present',
        policy_setting: 'AuditAccountLogon',
        policy_type: 'Event Audit',
        policy_value: 'Success,Failure',
      )
      expect(resource[:ensure]).to eq(:present)
    end

    it 'raises an error with bad policy event audit value' do
      expect {
        Puppet::Type.type(:local_security_policy).new(
          name: 'Audit account logon events',
          ensure: 'present',
          policy_setting: 'AuditAccountLogon',
          policy_type: 'Event Audit',
          policy_value: 'Success.Failure', # Intentional typo '.' instead of ','
        )
      }.to raise_error(Puppet::ResourceError)
    end

    it 'creates a system access value' do
      resource = Puppet::Type.type(:local_security_policy).new(
        name: 'Accounts: Administrator account status',
        ensure: 'present',
        policy_setting: 'EnableAdminAccount',
        policy_type: 'System Access',
        policy_value: '0',
      )
      expect(resource[:ensure]).to eq(:present)
    end

    it 'raises an error with with bad value for Administrator account status' do
      expect {
        Puppet::Type.type(:local_security_policy).new(
          name: 'Administrator account status',
          ensure: 'present',
          policy_setting: 'EnableAdminAccount',
          policy_type: 'System Access',
          policy_value: '0',
        )
      }.to raise_error(Puppet::ResourceError)
    end
  end
end
