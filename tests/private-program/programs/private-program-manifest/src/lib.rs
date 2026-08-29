use anchor_lang::prelude::*;

declare_id!("Lamports11111111111111111111111111111111111");

#[program]
pub mod private_program_manifest {
    use super::*;

    pub fn manifest_private(_ctx: Context<ManifestPrivate>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct ManifestPrivate {}
