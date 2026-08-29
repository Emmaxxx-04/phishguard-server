package com.fishguard.mobile.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.fishguard.mobile.data.ThreatEntity
import com.fishguard.mobile.ui.theme.RiskCritical
import com.fishguard.mobile.ui.theme.RiskHigh
import com.fishguard.mobile.ui.theme.RiskLow
import com.fishguard.mobile.ui.theme.RiskMedium
import com.fishguard.mobile.ui.theme.RiskSafe

fun riskLabel(level: String): String = when (level) {
    "CRITICAL" -> "Critique"
    "HIGH" -> "Élevé"
    "MEDIUM" -> "Moyen"
    "LOW" -> "Faible"
    else -> "Sûr"
}

@Composable
fun riskColor(level: String) = when (level) {
    "CRITICAL" -> RiskCritical
    "HIGH" -> RiskHigh
    "MEDIUM" -> RiskMedium
    "LOW" -> RiskLow
    else -> RiskSafe
}

@Composable
fun RiskBadge(level: String, score: Int) {
    val color = riskColor(level)
    Text(
        text = "${riskLabel(level)} · $score/100",
        color = color,
        fontSize = 12.sp,
        fontWeight = FontWeight.Medium,
        modifier = Modifier
            .background(color.copy(alpha = 0.14f), RoundedCornerShape(6.dp))
            .padding(horizontal = 8.dp, vertical = 4.dp)
    )
}

@Composable
fun threatRowColor(threat: ThreatEntity) = riskColor(threat.riskLevel)
