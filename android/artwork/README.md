# Android launcher artwork

`ic_launcher.svg` and `ic_launcher_round.svg` are the editable sources for the pre-Android 8 legacy icons.
`ic_launcher_store.svg` is the unmasked, square source for the 512 px Play Store icon; Google Play applies its own
corner mask and shadow. The adaptive foreground and Android 13 monochrome artwork use matching Android vector
drawables under `app/src/main/res/drawable`.

Regenerate the committed PNG assets with librsvg installed:

```bash
android/artwork/generate-launcher-icons.sh
```

Keep the meaningful foreground inside the adaptive icon's central 66 × 66 dp safe zone so circular, rounded-square,
squircle, and vendor-specific masks do not clip the mark.
