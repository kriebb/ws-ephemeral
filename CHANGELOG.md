# CHANGELOG

<!-- version list -->

## v1.3.4 (2025-12-16)

### Bug Fixes

- **changelog**: Delete old changelog to force regeneration
  ([`1d9927b`](https://github.com/kriebb/ws-ephemeral/commit/1d9927b440cf80688a6f70aa20a4ba40feaf9a6a))


## v1.3.3 (2025-12-16)

### Bug Fixes

- **ws**: Update docstring and refactor release config
  ([`de82b49`](https://github.com/kriebb/ws-ephemeral/commit/de82b49874a79185d5598903fcd5b4d38f4dbae9))

### Chores

- **release**: Update semantic-release config for v10 compatibility
  ([`27d3091`](https://github.com/kriebb/ws-ephemeral/commit/27d3091ae08e6275301560f3155654f084f69219))


## v1.3.2 (2025-12-16)

### Bug Fixes

- **ws**: Update docstring for renew_csrf
  ([`d59dfee`](https://github.com/kriebb/ws-ephemeral/commit/d59dfeee901407ca7fb85381a104645dab412ba2))

### Chores

- **release**: 1.3.2 [skip ci]
  ([`b66b270`](https://github.com/kriebb/ws-ephemeral/commit/b66b27092beb45a6e4b24375d642c051a2e89267))

### Continuous Integration

- Unify test, release and docker build into single workflow
  ([`6304f10`](https://github.com/kriebb/ws-ephemeral/commit/6304f10eef1cfa573302e23db2da4f114e8a62f2))

- **release**: Use PAT to trigger docker build on release
  ([`c21f6ee`](https://github.com/kriebb/ws-ephemeral/commit/c21f6eee2a86de6d9f2daedc209dd63bdac9a878))

### Documentation

- **changelog**: Add fork disclaimer
  ([`525547e`](https://github.com/kriebb/ws-ephemeral/commit/525547e9201a8ae551eb3ee60744cd4ce7c38f9f))

- **readme**: Clean up deprecated info and roadmap
  ([`0639c80`](https://github.com/kriebb/ws-ephemeral/commit/0639c80c7bad973421abf1cf378d118009d1a410))

- **readme**: Fix markdown alert formatting for attention/caution
  ([`ca47005`](https://github.com/kriebb/ws-ephemeral/commit/ca470052930acc709995d59df84578780104d702))


## v1.3.1 (2025-12-16)

### Bug Fixes

- **test**: Update tests to handle login side effects and mock request url
  ([`368210d`](https://github.com/kriebb/ws-ephemeral/commit/368210da2a3673f070f0e78dbf4e0f3608dd8bbc))

### Chores

- **release**: 1.3.1 [skip ci]
  ([`ca81b28`](https://github.com/kriebb/ws-ephemeral/commit/ca81b28ae45bd04e0cdb2ac6bba3de76cca13edb))

### Documentation

- **readme**: Add healthcheck configuration instructions
  ([`665ce2a`](https://github.com/kriebb/ws-ephemeral/commit/665ce2a6fa3eac925ac63916c9dabd4434f551a2))


## v1.3.0 (2025-12-16)

### Chores

- **release**: 1.3.0 [skip ci]
  ([`e4b984b`](https://github.com/kriebb/ws-ephemeral/commit/e4b984bfd6206b5470047354e266fe0706136c47))

### Features

- **healthcheck**: Add healthcheck script and docker integration
  ([`ecffd08`](https://github.com/kriebb/ws-ephemeral/commit/ecffd081b1ddcedf032775b2b623021559266d40))


## v1.2.1 (2025-12-16)

### Bug Fixes

- **ci**: Set dummy env vars for tests to prevent SystemExit
  ([`e13df41`](https://github.com/kriebb/ws-ephemeral/commit/e13df41281f542aecb3f909ae79ed1d6a08c8975))

### Chores

- **release**: 1.2.1 [skip ci]
  ([`05c956f`](https://github.com/kriebb/ws-ephemeral/commit/05c956feb6ade1096c4d898ea1715c745b1cad54))


## v1.2.0 (2025-12-16)

### Chores

- **release**: 1.2.0 [skip ci]
  ([`0f000e0`](https://github.com/kriebb/ws-ephemeral/commit/0f000e0c79481a0a00dd965baf96dea4de2cd877))

### Features

- **ws**: Implement dynamic salt extraction
  ([`fd1869c`](https://github.com/kriebb/ws-ephemeral/commit/fd1869c3c40e699e21a416d7a384d4f66d615ed9))

### Testing

- **ws**: Add tests for new 2-stage login flow
  ([`73585c8`](https://github.com/kriebb/ws-ephemeral/commit/73585c813f2cf2ec577101a3a3ff4f2505ef62db))


## v1.1.2 (2025-12-16)

### Bug Fixes

- **ws**: Implement new 2-stage login flow
  ([`442a3e9`](https://github.com/kriebb/ws-ephemeral/commit/442a3e9853b69419f235b44104a98b208aae7e23))

### Chores

- **release**: 1.1.2 [skip ci]
  ([`2fc368e`](https://github.com/kriebb/ws-ephemeral/commit/2fc368e9b66e837394fcabca4403a224269b4996))


## v1.1.1 (2025-12-16)

### Bug Fixes

- **ci**: Align test imports and PYTHONPATH to src dir
  ([`100d420`](https://github.com/kriebb/ws-ephemeral/commit/100d4206fd0a1fa7ccecc5f369dc0336f97270fc))

### Chores

- **release**: 1.1.1 [skip ci]
  ([`9660695`](https://github.com/kriebb/ws-ephemeral/commit/9660695fc821876a4430fb96a8c7ac1da6fbc0b5))


## v1.1.0 (2025-12-16)

### Chores

- **release**: 1.1.0 [skip ci]
  ([`5f79497`](https://github.com/kriebb/ws-ephemeral/commit/5f794975da8aa28d9a86c1ab3a08727a69cdb03e))

### Features

- **ws**: Dump cookies in debug info
  ([`7953243`](https://github.com/kriebb/ws-ephemeral/commit/7953243458c365b8213b689827a0f95e72602742))

- **ws**: Dump debug html and fix cookie conflict
  ([`480ea92`](https://github.com/kriebb/ws-ephemeral/commit/480ea929d3c9f724b0badf11293dd249c58d5ea6))


## v1.0.7 (2025-12-16)

### Bug Fixes

- **ci**: Correct PYTHONPATH to allow src imports in tests
  ([`5251eb0`](https://github.com/kriebb/ws-ephemeral/commit/5251eb090d1e3ce25c80e74df63fc3b13aeea0d3))

### Chores

- **release**: 1.0.7 [skip ci]
  ([`ae0d872`](https://github.com/kriebb/ws-ephemeral/commit/ae0d8723d63892dd4e19fedf4fcaa208a7f71a9a))


## v1.0.6 (2025-12-16)

### Bug Fixes

- **ci**: Explicitly configure changelog update in pyproject.toml
  ([`ec97d85`](https://github.com/kriebb/ws-ephemeral/commit/ec97d85edb7e336f39982d7fcb521d8f7989cb01))

- **ci**: Use correct poetry lock command
  ([`9fd0a94`](https://github.com/kriebb/ws-ephemeral/commit/9fd0a94b7fe08caa94d8317ed9ba4e17051a3761))

### Chores

- **release**: 1.0.6 [skip ci]
  ([`ae1249f`](https://github.com/kriebb/ws-ephemeral/commit/ae1249ffb477d0b4c6f153a3784e99d38264f3f7))

### Testing

- **ws**: Update tests to simulate follow_redirects behavior
  ([`3ee7d46`](https://github.com/kriebb/ws-ephemeral/commit/3ee7d467e1c5e2c61eeb732a7468ed9248ceac1b))


## v1.0.5 (2025-12-16)

### Bug Fixes

- **ci**: Add pytest to dependencies and regen lock in CI
  ([`4cc3ec6`](https://github.com/kriebb/ws-ephemeral/commit/4cc3ec60a8f936e7d9f6865e21198c3b6100e23b))

### Chores

- **release**: 1.0.5 [skip ci]
  ([`4ccba78`](https://github.com/kriebb/ws-ephemeral/commit/4ccba78f502ff48b16142e6a70b77954d52eedfc))


## v1.0.4 (2025-12-16)

### Bug Fixes

- **ws**: Enable follow_redirects and update session expiry check
  ([`16c917a`](https://github.com/kriebb/ws-ephemeral/commit/16c917a000cc24c7e40e3c9ce7142b715346f662))

### Chores

- **release**: 1.0.4 [skip ci]
  ([`c726956`](https://github.com/kriebb/ws-ephemeral/commit/c726956cf36ccd8ef7665f841cc42a5b67ebb015))


## v1.0.3 (2025-12-16)

### Bug Fixes

- **ws**: Add debug logging to login response
  ([`9c45e90`](https://github.com/kriebb/ws-ephemeral/commit/9c45e90ce41b3d42bc4d08b000c621d93ae136aa))

### Chores

- **release**: 1.0.3 [skip ci]
  ([`0e7ceec`](https://github.com/kriebb/ws-ephemeral/commit/0e7ceec257bcd87d7b3771e7c53ffc27f1691f43))


## v1.0.2 (2025-12-16)

### Bug Fixes

- **ci**: Invalidate cache and force dev dependencies install
  ([`2626dd0`](https://github.com/kriebb/ws-ephemeral/commit/2626dd03597bee1349413c6875aa8856a1b0b284))

### Chores

- **release**: 1.0.2 [skip ci]
  ([`d67975a`](https://github.com/kriebb/ws-ephemeral/commit/d67975a2ec2c060e2dfdc645615b1a53dac9949e))


## v1.0.1 (2025-12-16)

### Bug Fixes

- **ci**: Ensure poetry install runs and use poetry run for tests
  ([`6c876de`](https://github.com/kriebb/ws-ephemeral/commit/6c876de4f3a453340dc034d25bdbf3d62ba8c9c1))

### Chores

- **release**: 1.0.1 [skip ci]
  ([`aa20633`](https://github.com/kriebb/ws-ephemeral/commit/aa206336ed6844f1b00e15e57e2df61e8c193e42))


## v1.0.0 (2025-12-16)

- Initial Release
