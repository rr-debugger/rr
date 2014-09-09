Please make sure you go through this list before submitting a patch.  The rules aren't hard and fast, but mostly adhering to them will make for quicker mergings.

- [ ] Does your PR add support for a new kernel API?  For example, supporting a new syscall.  If so, your patch should include at least one new test for the API.  This is usually pretty easy.  See `$rr/src/test` for examples.

- [ ] Did you run the rr test suite (including your new tests, if any), and pass all the tests?  `make -C $objdir check`.  Unfortunately, rr doesn't have automated infrastructure that can run the tests yet, so developers have to run them locally.

- [ ] If you created new files for your PR, did you `git add` them?  Habitually (or with a script or push hook) checking `git status` is a good habit to acquire.

- [ ] If you changed the trace layout or format, did you bump `TRACE_VERSION_NUMBER`?

- [ ] If you added new command-line parameters, did you update `print_usage()` to document them?

- [ ] Does your PR apply cleanly on top of upstream/master HEAD?  It's dangerous to have someone else sort out your merge conflicts, so just don't do it.  Best of all is to have a PR *rebased* on top of upstream/master HEAD, so that the merge is simply a fast-forward.

- [ ] If your PR includes multiple changesets, do they all (i) build cleanly in sequence; (ii) pass all tests in sequence?  This is important for bisecting over commit history.

- [ ] If your PR is a very large-scale change (for example, a rewrite in Rust to use the visitor pattern), did you discuss the proposed changes in an issue or the mailing list?  It's hard to review large patches that just fall in ones lap.  It's much easier to discuss the important changes at a high level and then approach the patch knowing what's important and what's not.

- [ ] If your PR is large or includes many changesets, would it have been possible to break the changes into a series of smaller PRs?  For example, it's hard to review a big patch that, say, fixes whitespace errors in a file along with a one-line, important, bug fix.  It's much easier to review one PR that fixes whitespace (which can just be skimmed), and then review another PR that makes the one-line bug fix (which would be scrutinized more).  This approach is also better for the patch author in that it usually allows the work to land faster, and reduces the burden of continually un-bit-rotting large, trivial, changes.

- [ ] Did you check your code is formatted correctly? It's easiest to run
````
find src include -name '*.cc' -or -name '*.h' -or -name '*.c'|xargs clang-format -i -style=file
````
on each commit.
