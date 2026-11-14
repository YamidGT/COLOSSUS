# Six-slide COLOSSUS pitch

Standalone HTML presentation for GitHub Pages. No build, credentials, API calls or target execution. Publish this directory as the Pages artifact. Links are relative for project Pages hosting.

Local preview: `python3 -m http.server 8769 --directory presentation`, then open `http://127.0.0.1:8769`.

- Arrow keys or Page Up/Down: previous/next slide. Home/End: first/last.
- Slide markers and `#1` through `#6` provide direct navigation.
- Full screen button uses the browser fullscreen API.
- Speaker notes are optional and contain scope/denominator detail.
- Browser Print produces six landscape pages. Reduced motion is respected.
- The separate recorded demo is linked at https://colossus-defence-demo.netlify.app.

All measurements come from `docs/submission-evidence.json` and `evaluation/submission/`. These are measured development results, not public benchmark scores. Costs are recorded model usage estimates at configured rates, excluding compute, prior development and billing reconciliation. The DSVW repair remains formally unsupported. The formal component is an owned authorization fixture.

Source baseline: `17faf61`. This presentation changes no runtime contracts or application behavior.

Validation: `node --check presentation/deck.js` passed. Static checks confirmed exactly six slides, unique IDs, required reported measurements and relative asset files. Core text/background contrast measured 5.70:1 or higher. Visual browser inspection is performed by the integrator before publication.

Publication target: https://danidiaztech.github.io/colossus-presentation/ . The `DaniDiazTech/colossus-presentation` publication repository contains only these static files. The implementation and evidence remain in `YamidGT/COLOSSUS`.


Pitch revision: opening chart uses annual published CVE records through complete year 2025 from https://www.cve.org/About/Metrics (accessed 14 November 2026). It starts at zero and excludes partial 2026 counts. The 7.5× ratio is 48,244 / 6,457; 20.4% growth is 48,244 / 40,077 - 1. These figures measure published records, not all discovered vulnerabilities or AI causation.

The two diagrams in `assets/` were supplied by the user. Slide 2 toggles them without adding a seventh slide and links the full-resolution originals. Formal verification appears as the implemented toolkit with the owned component experiment. Exact target linkage limitations remain in speaker notes. Result bars share a 0–360 second scale and separate the 300-second observation from other elapsed cycle work. Asset URLs use `?v=2` to avoid stale presentation caches.
