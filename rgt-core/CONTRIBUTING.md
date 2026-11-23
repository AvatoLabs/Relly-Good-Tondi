Contributing guidelines
=======================

Contributions are very welcome. When contributing code, please follow these
simple guidelines.

#### Table Of Contents
- [Contribution workflow](#contribution-workflow)
    * [Proposing changes](#proposing-changes)
    * [Preparing PRs](#preparing-prs)
    * [Peer review](#peer-review)
- [Coding conventions](#coding-conventions)
- [Security](#security)
- [Testing](#testing)
- [Going further](#going-further)

Overview
--------

* Before adding any code dependencies, check with the maintainers if this is okay.
* Write properly formatted comments: they should be English sentences, eg:

        // Return the current UNIX time.

* Read the DCO and make sure all commits are signed off, using `git commit -s`.
* Follow the guidelines when proposing code changes (see below).
* Write properly formatted git commits (see below).
* Run the tests with `cargo test --workspace --all-features`.
* Make sure you run `rustfmt` on your code (see below details).
* Please don't file an issue to ask a question. Each repository - or  
  GitHub organization has a "Discussions" with Q&A section; please post your
  questions there. You'll get faster results by using this channel.

Contribution Workflow
---------------------
Review changes against the v10 Note publication rules, certified execution receipts and client-side validation.

Overall, have fun :)

[1]: http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html
