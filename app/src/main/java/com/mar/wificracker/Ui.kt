package com.mar.wificracker

import android.content.Context
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.util.TypedValue
import android.view.Gravity
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.*

/** Палитра и хелперы вёрстки — единый тёмный стиль. */
object Ui {
    const val BG = 0xFF0E1116.toInt()
    const val SURFACE = 0xFF171B21.toInt()
    const val SURFACE2 = 0xFF1F2530.toInt()
    const val ACCENT = 0xFFFF8A2B.toInt()
    const val TEXT = 0xFFE6EDF3.toInt()
    const val SUB = 0xFF8B98A5.toInt()
    const val OK = 0xFF3FB950.toInt()
    const val PMKID = 0xFF388BFD.toInt()
    const val HS = 0xFFD29922.toInt()
    const val DANGER = 0xFFF85149.toInt()

    fun Context.dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    fun card(ctx: Context): LinearLayout {
        val l = LinearLayout(ctx)
        l.orientation = LinearLayout.VERTICAL
        val bg = GradientDrawable()
        bg.cornerRadius = ctx.dp(14).toFloat(); bg.setColor(SURFACE)
        bg.setStroke(ctx.dp(1), 0xFF2A313C.toInt())
        l.background = bg
        val pad = ctx.dp(14); l.setPadding(pad, pad, pad, pad)
        return l
    }

    fun button(ctx: Context, text: String, color: Int = ACCENT, textColor: Int = 0xFF241200.toInt()): Button {
        val b = Button(ctx); b.text = text; b.isAllCaps = false
        b.setTextColor(textColor); b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
        val bg = GradientDrawable(); bg.cornerRadius = ctx.dp(12).toFloat(); bg.setColor(color)
        b.background = bg; b.stateListAnimator = null
        b.setPadding(ctx.dp(12), ctx.dp(8), ctx.dp(12), ctx.dp(8))
        return b
    }

    fun tv(ctx: Context, text: String, size: Float = 14f, color: Int = TEXT, bold: Boolean = false): TextView {
        val t = TextView(ctx); t.text = text; t.setTextColor(color)
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, size)
        if (bold) t.setTypeface(t.typeface, android.graphics.Typeface.BOLD)
        return t
    }

    fun badge(ctx: Context, text: String, color: Int): TextView {
        val t = tv(ctx, text, 11f, Color.WHITE, true)
        val bg = GradientDrawable(); bg.cornerRadius = ctx.dp(6).toFloat(); bg.setColor(color)
        t.background = bg; t.setPadding(ctx.dp(8), ctx.dp(3), ctx.dp(8), ctx.dp(3))
        return t
    }

    fun lpRow() = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
    fun lpW() = LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT)
}
