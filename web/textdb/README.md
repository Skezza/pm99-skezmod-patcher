# SkezMod Patcher browser build

This interface uses the TextDB browser modules and WebAssembly engine from
Skezza/pm99-textdb at 668519a4c2fe5df5052fea9c5b48e20189280914. The engine in `assets/` was built with Emscripten 4.0.10 using TextDB’s `make web-core` target. The Pages build checks both asset hashes before publishing. For a local preview, serve this directory on localhost.
Run `npm test` for the browser module tests.

Choose the English retail installation files to build a game update directly
or export editable TextDB tables. An extracted and edited TextDB package can
also build a game update. The original table export is checked against the
retail hashes. The Stars option applies only to game updates and changes the
club directory ID after the table build succeeds.

A game update can include a user-supplied 32-bit Windows `ddraw.dll` with its
`ddraw.ini` or `dgVoodoo.conf` placed at the ZIP root. The patcher checks the
DLL header and packages those files as supplied. Compatibility with PM99
depends on the rendering fix. The site distributes no rendering DLL.
