# Third-party notices

kalitka is licensed under AGPL-3.0-or-later (see `LICENSE`). It depends on the
following third-party packages, whose licenses are all compatible with that use.
Each remains under its own license and copyright.

| Package | Version | License |
| --- | --- | --- |
| [MaxMind.GeoIP2](https://github.com/maxmind/GeoIP2-dotnet) | 6.1.0 | Apache-2.0 |
| [Microsoft.Data.Sqlite](https://github.com/dotnet/efcore) | 9.0.0 | MIT |
| [Npgsql](https://github.com/npgsql/npgsql) | 10.0.3 | PostgreSQL License (BSD-style) |

The runtime is .NET 9 (MIT). Transitive dependencies of the packages above are
covered by their respective licenses.

MaxMind.GeoIP2 is distributed under the Apache License 2.0, which requires that
this attribution be preserved. No MaxMind data is bundled with kalitka; the
optional local geo lookup reads a GeoLite2/GeoIP2 database that the operator
provides separately, under MaxMind's own end-user license.

The test suite additionally uses MaxMind's synthetic `GeoIP2-City-Test.mmdb`
(Apache-2.0), which is used only for testing and is not distributed as part of the
application.
