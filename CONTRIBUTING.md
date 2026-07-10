# Contributing

## Setup

```bash
git clone https://github.com/NeuralInverse/soc2.git
cd soc2
npm install
```

## Adding rules

Each file under `src/rules/` exports an `ISoc2Rule[]` array. Pick the relevant file for the SOC 2 criteria you are implementing and add rules following the existing type.

Run `npm run typecheck` before pushing — must pass with 0 errors.

## Rule ID format

`soc2-{category}-{NNN}` — e.g. `soc2-cc6-042`, `soc2-p3-007`

IDs must be unique across the entire package.

## Commit format

```
feat(cc6): add 20 access control rules for CC6.1-CC6.3
fix(cc5): correct regex for SQL injection pattern
```

## Questions

Open an issue or email [support@neuralinverse.com](mailto:support@neuralinverse.com)
