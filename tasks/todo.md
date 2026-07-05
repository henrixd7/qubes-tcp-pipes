## Routing signature compatibility check

- [x] Inspect current `route_connection` call sites and data models.
- [x] Remove or fix the broken compatibility branch without changing normal UI routing.
- [x] Add regression coverage for supported routing calls and lane tracking.
- [x] Run tests and document the verification result.

### Review

- Removed the broken compatibility branch from `route_connection`; current UI calls pass VM objects directly, and `VM` has no `local_port`/`remote_port` attributes.
- Passed `conn_id=conn` from the UI so route-time lane reservations use the same identity as draw-time `lane_x()`/`lane_y()` calls.
- Added routing regression tests for the supported UI call signature and connection identity lane registration.
- Verification: `python -m unittest discover -s tests` passed, 7 tests.
