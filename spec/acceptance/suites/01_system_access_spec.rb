# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'local_security_policy' do
  [10, 20].each do |n|
    context "set system access policy (PasswordHistorySize=#{n})" do
      let(:manifest) do
        <<~END
          local_security_policy { 'Enforce password history':
            ensure       => present,
            policy_value => '#{n}',
          }
        END
      end

      it 'is expected to apply with no errors' do
        # Run twice to test idempotency
        apply_manifest(manifest, 'catch_failures' => true)
        apply_manifest(manifest, 'catch_changes' => true)
      end

      it 'sets the value correctly' do
        on hosts, 'Secedit /Export /Areas SecurityPolicy /CFG C:\secedit.txt'
        hosts.each do |host|
          value = on(host, 'type C:\secedit.txt')
          expect(value.output).to match(%r{^PasswordHistorySize\s*=\s*#{n}$})
        end
      end
    end
  end

  context 'rename guest account' do
    let(:manifest) do
      <<~END
        local_security_policy { 'Accounts: Rename guest account':
          ensure       => present,
          policy_value => '"lsp_guest"',
        }
      END
    end

    it 'is expected to apply with no errors' do
      # Run twice to test idempotency
      apply_manifest(manifest, 'catch_failures' => true)
      apply_manifest(manifest, 'catch_changes' => true)
    end
  end

  context 'rename administrator account' do
    let(:manifest) do
      <<~END
        local_security_policy { 'Accounts: Rename administrator account':
          ensure       => present,
          policy_value => '"lsp_admin"',
        }
      END
    end

    it 'is expected to apply with no errors' do
      # Run twice to test idempotency
      apply_manifest(manifest, 'catch_failures' => true)
      apply_manifest(manifest, 'catch_changes' => true)
    end
  end
end
