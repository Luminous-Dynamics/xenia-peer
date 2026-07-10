package io.luminousdynamics.xenia

/**
 * Linux evdev keycodes + modifier-bitmask convention, ported from
 * `xenia-viewer`'s own `egui_key_to_evdev`/`modifiers_bitmask`
 * (`apps/xenia-viewer/src/gui.rs`) -- same codes, Kotlin instead of
 * Rust, since Android's own `KeyEvent` keycodes are a different
 * numbering the daemon-side injectors don't understand.
 *
 * `charToKey` covers standard US-QWERTY printable ASCII, which is
 * enough for an IME-driven text-diff typing flow (see
 * `KeyboardBridge`) -- it's not a full physical-keyboard layout
 * (no dead keys, no non-US layouts).
 */
object EvdevKeys {
    // Modifier bits: bit0=Shift, bit1=Ctrl, bit2=Alt, bit3=Meta/Super.
    const val MOD_SHIFT: Int = 1 shl 0
    const val MOD_CTRL: Int = 1 shl 1
    const val MOD_ALT: Int = 1 shl 2
    const val MOD_META: Int = 1 shl 3

    const val ENTER: Int = 28
    const val BACKSPACE: Int = 14
    const val SPACE: Int = 57
    const val TAB: Int = 15
    const val ESCAPE: Int = 1
    const val ARROW_UP: Int = 103
    const val ARROW_DOWN: Int = 108
    const val ARROW_LEFT: Int = 105
    const val ARROW_RIGHT: Int = 106

    private val LETTER_CODES = mapOf(
        'a' to 30, 'b' to 48, 'c' to 46, 'd' to 32, 'e' to 18, 'f' to 33, 'g' to 34,
        'h' to 35, 'i' to 23, 'j' to 36, 'k' to 37, 'l' to 38, 'm' to 50, 'n' to 49,
        'o' to 24, 'p' to 25, 'q' to 16, 'r' to 19, 's' to 31, 't' to 20, 'u' to 22,
        'v' to 47, 'w' to 17, 'x' to 45, 'y' to 21, 'z' to 44,
    )
    private val DIGIT_CODES = mapOf(
        '0' to 11, '1' to 2, '2' to 3, '3' to 4, '4' to 5,
        '5' to 6, '6' to 7, '7' to 8, '8' to 9, '9' to 10,
    )
    // Unshifted-char to (code, needsShift). Shifted digit symbols
    // (!@#$...) reuse the digit's own key + shift, matching a real
    // US-QWERTY keyboard.
    private val PUNCTUATION_CODES = mapOf(
        '-' to (12 to false), '_' to (12 to true),
        '=' to (13 to false), '+' to (13 to true),
        ';' to (39 to false), ':' to (39 to true),
        '\'' to (40 to false), '"' to (40 to true),
        '`' to (41 to false), '~' to (41 to true),
        '\\' to (43 to false), '|' to (43 to true),
        ',' to (51 to false), '<' to (51 to true),
        '.' to (52 to false), '>' to (52 to true),
        '/' to (53 to false), '?' to (53 to true),
        '[' to (26 to false), '{' to (26 to true),
        ']' to (27 to false), '}' to (27 to true),
        '1' to (2 to false), '!' to (2 to true),
        '2' to (3 to false), '@' to (3 to true),
        '3' to (4 to false), '#' to (4 to true),
        '4' to (5 to false), '$' to (5 to true),
        '5' to (6 to false), '%' to (6 to true),
        '6' to (7 to false), '^' to (7 to true),
        '7' to (8 to false), '&' to (8 to true),
        '8' to (9 to false), '*' to (9 to true),
        '9' to (10 to false), '(' to (10 to true),
        '0' to (11 to false), ')' to (11 to true),
    )

    /** Map one typed character to (evdev code, whether Shift is needed). */
    fun charToKey(c: Char): Pair<Int, Boolean>? {
        if (c == ' ') return SPACE to false
        val lower = c.lowercaseChar()
        LETTER_CODES[lower]?.let { code -> return code to c.isUpperCase() }
        PUNCTUATION_CODES[c]?.let { return it }
        DIGIT_CODES[c]?.let { return it to false }
        return null
    }
}
