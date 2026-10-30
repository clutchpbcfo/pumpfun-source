# Lane w6r1-execute-sem: 0x22a10 `admin_cto::execute` (assembly-first semantic reconstruction)

Base: origin/main 099b0dd (1027 normalized / 276 raw). Target on base: 27,416 B (orig 27,400), ratio 0.36328, calls 154/3 (= orig).

## Trials

| trial | mechanism | bytes | ratio | normalized/raw | losses | ledger |
|---|---|---:|---:|---|---|---|
| base | origin/main 099b0dd | 27,416 | 0.36328 | 1027/276 | | |
| **t1** | sweep body as nested `fn sweep(ctx:&Context<AdminCto>,holder_key:&Pubkey)` (w4-admincto t1, ported) | 27,424 | **0.36952** | 1027/276 | none (no raw 0xa868 loss on current main) | 50ed472b |
| t2 | t1 + `holder.unwrap_or(false)`, `cashback=!holder&st.cashback` | 27,400 | 0.34871 | 1027/276 | none | ad8c526d |

## Mechanism (t1)

The original reloads `holder_creator_vault.key` in the 648 dest-check error path after the `error!` calls: the
sweep body reads the accounts through `&Context`, not through a closure environment that LLVM marks noalias.
A nested fn taking `&Context<AdminCto>` reproduces the reload.
