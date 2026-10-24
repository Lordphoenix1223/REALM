# Human-experience design and review

A short record of decisions for the public experience PR, not a usability study.
The seven current reference READMEs were inspected before implementation. Their
popularity is not treated as evidence that each presentation choice works.

| Reference | Useful principle | What REALM does differently |
| --- | --- | --- |
| [agent-skills](https://github.com/addyosmani/agent-skills) | Explicit value and a workflow diagram early. | Explain the evidence problem before commands or architecture. |
| [autoresearch](https://github.com/karpathy/autoresearch) | A memorable experiment and a small reproducible loop. | Use the real two-worker loop; avoid speculative capability claims. |
| [uv](https://github.com/astral-sh/uv) | Show the difference visually; offer a clear start. | Show an evidence gap, not a speed claim; disclose repeat structure. |
| [Oh My Zsh](https://github.com/ohmyzsh/ohmyzsh) | Conversational prose invites non-experts. | Keep warmth and direct questions, omit promotional/social badge clutter. |
| [nvm](https://github.com/nvm-sh/nvm) | Installation and troubleshooting remain discoverable. | A long table of contents is excessive for REALM's small preview. |
| [ripgrep](https://github.com/BurntSushi/ripgrep) | Concrete examples, comparisons and reasons not to use it. | Put scientific limits next to outcomes, with methods one click away. |
| [bat](https://github.com/sharkdp/bat) | Show actual behavior before detailed setup. | Lead with the paired-history story and an interactive frozen replay. |

No reference logo, screenshot, font, code or paragraph was copied. The new SVGs,
interface and prose are original REALM material under MIT OR Apache-2.0, with AI
coding assistance. The graphite/teal identity is preserved. Theme-aware vector
story cards have accessible descriptions and a narrow, vertically ordered layout.

## Information architecture

[Diátaxis](https://diataxis.fr/) separates learning, practical tasks, explanation
and reference. Existing important documents were retained; we removed repetition
from the onboarding path rather than deleting evidence or legal files.

| Markdown | Role / action |
| --- | --- |
| Root README | Rewritten human introduction, visual story, demo, quickstart, findings and contribution routes. |
| INSTALL | Beginner source setup; adds the no-install replay route and clarifies that native binaries are not published. |
| docs/USAGE | New task-oriented guide; consolidates old README CLI recipes, exits, record import and viewer instructions. |
| docs/README | New task-based navigation; replaces the README's scattered operational/manifest links. |
| docs/COUNTEREXAMPLE | Scientific explanation and observer/checker distinction; preserved. |
| benchmarks/README; benchmarks/reference/README | Methods, limitations and retained reference evidence; preserved. |
| docs/ARTIFACT_FORMAT | Technical reference; preserved, one level below practical use. |
| CONTRIBUTING; CHANGELOG | Adds a Rust-free static/prose contribution path; release history is preserved. |
| docs/MAINTAINERS; docs/RELEASING; docs/CONTENTS | Specialized operational/reference paths, preserved behind the documentation map. |
| docs/DEPLOY_WALKTHROUGH | Maintainer reproduction/deployment instructions, not the first-time path. |
| site/evidence/README | Prepared-report provenance and reproducibility; separated from live local verification. |
| AGENTS | Root location and contents preserved so development agents still discover it. |
| RIGHTS; SECURITY; third-party/minimal-lexical-0.2.1/LICENSE | Required license, attribution and security material; unchanged. |
| This design note | Review context, off the primary onboarding path. |

No useful document was replaced by a giant combined guide. The new usage guide
absorbs the detailed commands removed from README. Required JSON provenance,
manifest and all third-party texts remain intact. No research architecture changed.

## Review standard

The four audience journeys are internal walkthroughs, not real participant tests:
visitor → premise and replay; developer → source setup and real example;
researcher → methods, case study and negative results; contributor → bounded
starter issues. Actual browser interactions, dimensions, keyboard behavior,
contrast and prepared/native report parity are recorded with the PR screenshots.
Do not call those checks a human user study or claim a measured improvement in
comprehension without external participants.

The strongest finding remains a limitation: passing task tests and identical,
internally valid artifacts can coexist with different execution histories. The
independent cooperative harness sees a temporary write; the artifact checker
does not detect it. Execution authorization remains INCOMPLETE. Benchmark A is
18 fixture variants repeated five times; B has zero REALM runtime-policy detections
among 60 planted violations. This presentation changes neither experiment.
