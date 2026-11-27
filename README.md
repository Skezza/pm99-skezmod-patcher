# SkezMod Patcher for Premier Manager 99

SkezMod Patcher is a standalone browser tool for the English retail release. The page reads your club database locally and downloads a replacement.

1. Open the hosted patcher, or serve the `web/` directory locally with `python3 -m http.server 8097 --bind 127.0.0.1 --directory web` and open [the local patcher](http://127.0.0.1:8097/).
2. Select `DBDAT/EQ98030.FDI` from your game folder.
3. Leave **Fix the Stars player crash** ticked to move the Stars club record from ID 9900 to 9899. The question-mark button explains the change. Untick the box to download your selected file unchanged.
4. Back up the club database in your game folder before replacing it with the download.

The Stars roster stays intact. The browser release leaves `MANAGPRE.EXE` and `JUG98030.FDI` untouched. It accepts the pinned stock database and the same database with the ID fix already applied. An unticked box leaves an already fixed input as supplied.

The browser patcher is separate from the TextDB editor. The original Python patcher remains in the repository for users of the earlier release.

## Verification

Run `node --test web/test/stars.test.cjs`. Set `SKEZMOD_TEST_EQ` to your own stock EQ file to run the retail byte comparison. No game files are distributed with this repository.
