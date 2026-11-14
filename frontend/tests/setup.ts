import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'

afterEach(() => { cleanup(); window.history.replaceState(null, '', '/') })

// jsdom does not implement modal <dialog>. This shim only toggles the `open` state so component
// focus logic can be exercised; native top-layer inertness is NOT verified by these tests.
const proto = HTMLDialogElement.prototype
if (typeof proto.showModal !== 'function') {
  proto.showModal = function (this: HTMLDialogElement) { this.setAttribute('open', '') }
  proto.close = function (this: HTMLDialogElement) {
    if (!this.hasAttribute('open')) return
    this.removeAttribute('open'); this.dispatchEvent(new Event('close'))
  }
}
