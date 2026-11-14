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
