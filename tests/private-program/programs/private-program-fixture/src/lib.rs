use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

anchor_lang::program_security_txt!(
    name: "PRIVATE_FIXTURE_PROJECT_NAME",
    project_url: "https://private-fixture.invalid/project",
    contacts: "mailto:PRIVATE_FIXTURE_CONTACT@example.invalid",
    policy: "https://private-fixture.invalid/policy",
    source_code: "https://private-fixture.invalid/source",
    source_release: "private-fixture-v1",
    source_revision: "private-fixture-revision",
    auditors: "PRIVATE_FIXTURE_AUDITOR",
    acknowledgements: "PRIVATE_FIXTURE_ACKNOWLEDGEMENT",
);

#[program]
pub mod private_program_fixture {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, value: u64) -> Result<()> {
        ctx.accounts.state.value = value;
        Ok(())
    }

    pub fn set_value(ctx: Context<SetValue>, value: u64) -> Result<()> {
        ctx.accounts.state.value = value;
        Ok(())
    }

    pub fn fail_comparison(_ctx: Context<NoAccounts>, left: u64, right: u64) -> Result<()> {
        require_eq!(left, right, PrivateFixtureError::ValuesMustMatch);
        Ok(())
    }

    pub fn fail_custom(_ctx: Context<NoAccounts>) -> Result<()> {
        err!(PrivateFixtureError::ValuesMustMatch)
    }

    pub fn fail_error_macro(_ctx: Context<NoAccounts>) -> Result<()> {
        Err(error!(PrivateFixtureError::ValuesMustMatch))
    }

    pub fn fail_require(_ctx: Context<NoAccounts>) -> Result<()> {
        require!(false, PrivateFixtureError::ValuesMustMatch);
        Ok(())
    }

    pub fn fail_neq(_ctx: Context<NoAccounts>) -> Result<()> {
        require_neq!(7u64, 7u64, PrivateFixtureError::ValuesMustMatch);
        Ok(())
    }

    pub fn fail_gt(_ctx: Context<NoAccounts>) -> Result<()> {
        require_gt!(7u64, 9u64, PrivateFixtureError::ValuesMustMatch);
        Ok(())
    }

    pub fn fail_gte(_ctx: Context<NoAccounts>) -> Result<()> {
        require_gte!(7u64, 9u64, PrivateFixtureError::ValuesMustMatch);
        Ok(())
    }

    pub fn fail_keys_eq(_ctx: Context<NoAccounts>) -> Result<()> {
        require_keys_eq!(
            Pubkey::new_from_array([1; 32]),
            Pubkey::new_from_array([2; 32]),
            PrivateFixtureError::ValuesMustMatch
        );
        Ok(())
    }

    pub fn fail_keys_neq(_ctx: Context<NoAccounts>) -> Result<()> {
        let key = Pubkey::new_from_array([3; 32]);
        require_keys_neq!(key, key, PrivateFixtureError::ValuesMustMatch);
        Ok(())
    }

    pub fn explicit_protocol_log(_ctx: Context<NoAccounts>) -> Result<()> {
        msg!("PRIVATE_FIXTURE_SEMANTIC_RUNTIME_LOG https://example.invalid/src/runtime.rs");
        anchor_lang::solana_program::log::sol_log_data(&[b"PRIVATE_FIXTURE_SEMANTIC_DATA"]);
        Ok(())
    }

    pub fn panic_site(_ctx: Context<NoAccounts>) -> Result<()> {
        panic!("PRIVATE_FIXTURE_PANIC_DIAGNOSTIC")
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = payer, space = 8 + State::INIT_SPACE)]
    pub state: Account<'info, State>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetValue<'info> {
    #[account(mut)]
    pub state: Account<'info, State>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct NoAccounts {}

#[account]
#[derive(InitSpace)]
pub struct State {
    pub value: u64,
}

#[error_code]
pub enum PrivateFixtureError {
    #[msg("PRIVATE_FIXTURE_ERROR_MESSAGE")]
    ValuesMustMatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_error_contains_documentation() {
        let error: Error = PrivateFixtureError::ValuesMustMatch.into();
        let Error::AnchorError(error) = error else {
            panic!("expected Anchor error");
        };
        assert_eq!(error.error_name, "ValuesMustMatch");
        assert_eq!(error.error_msg, "PRIVATE_FIXTURE_ERROR_MESSAGE");
    }
}
