use anchor_lang::prelude::*;

declare_id!("Mu1tip1eErrors11111111111111111111111111111");

#[program]
pub mod private_program_secondary {
    use super::*;

    pub fn ping(_ctx: Context<Ping>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Ping {}
