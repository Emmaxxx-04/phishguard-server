package com.fishguard.mobile.ui.learn

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fishguard.mobile.ui.theme.FishGuardTheme
import com.fishguard.mobile.ui.theme.RiskCritical
import com.fishguard.mobile.ui.theme.RiskSafe

@Composable
fun LearnScreen() {
    val colors = FishGuardTheme.colors
    var expandedTitle by rememberSaveable { mutableStateOf<String?>(null) }

    Column(Modifier.fillMaxSize().padding(horizontal = 20.dp, vertical = 20.dp)) {
        Text("S'informer", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Les bons réflexes pour se protéger, au-delà de ce que FishGuard détecte automatiquement.",
            color = colors.textMuted,
            modifier = Modifier.padding(top = 4.dp, bottom = 18.dp)
        )

        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items(LearnContent.articles, key = { it.title }) { article ->
                ArticleCard(
                    article = article,
                    expanded = expandedTitle == article.title,
                    onToggle = { expandedTitle = if (expandedTitle == article.title) null else article.title }
                )
            }
            item { Spacer(Modifier.height(12.dp)) }
        }
    }
}

@Composable
private fun ArticleCard(article: LearnArticle, expanded: Boolean, onToggle: () -> Unit) {
    val colors = FishGuardTheme.colors

    Card(
        colors = CardDefaults.cardColors(containerColor = colors.surface),
        border = BorderStroke(1.dp, colors.line),
        shape = RoundedCornerShape(14.dp),
        modifier = Modifier.fillMaxWidth().animateContentSize()
    ) {
        Column(Modifier.clickable(onClick = onToggle).padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier
                        .size(38.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.14f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(article.icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                }
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(article.title, fontWeight = FontWeight.Medium)
                    Text(article.summary, color = colors.textMuted, style = MaterialTheme.typography.labelSmall)
                }
                Icon(
                    if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                    contentDescription = null,
                    tint = colors.textMuted
                )
            }

            if (expanded) {
                Spacer(Modifier.height(14.dp))
                TipGroup(title = "À faire", tint = RiskSafe, icon = Icons.Filled.Check, tips = article.doThis)
                Spacer(Modifier.height(10.dp))
                TipGroup(title = "À éviter", tint = RiskCritical, icon = Icons.Filled.Close, tips = article.avoidThis)
            }
        }
    }
}

@Composable
private fun TipGroup(title: String, tint: androidx.compose.ui.graphics.Color, icon: androidx.compose.ui.graphics.vector.ImageVector, tips: List<String>) {
    val colors = FishGuardTheme.colors
    Column {
        Text(title, color = tint, fontWeight = FontWeight.Medium, style = MaterialTheme.typography.labelSmall)
        Column(Modifier.padding(top = 6.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            tips.forEach { tip ->
                Row {
                    Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(16.dp).padding(top = 2.dp))
                    Text(tip, color = colors.textMuted, modifier = Modifier.padding(start = 8.dp))
                }
            }
        }
    }
}
