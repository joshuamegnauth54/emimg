Emimg is a petite, sandboxed image viewer.

---

## Goals

* Sandbox the program using operating system primitives like [seccomp](https://www.man7.org/linux/man-pages/man2/seccomp.2.html)
* Display image(s) in a box

## Non-goals

* Configuration
* Deleting files
* Disabling sandbox
* GUI
* Graphics APIs other than Vulkan
* Image editing
* Loading files over a network
* Opening new images
* Supporting older kernels or older operating systems
