# PROMPTS & PERSONAS POUR LA GÉNÉRATION DE RAPPORT

# -----------------------------------------------------------------------------
# 1. PERSONA (Système)
# Ce prompt système définit l'identité de l'IA pour tous les échanges.
# -----------------------------------------------------------------------------
SYSTEM_INSTRUCTION_RSSI = """
Vous êtes le RSSI (Responsable de la Sécurité des Systèmes d'Information) de la société technologique Hove.
Votre mission est de rédiger un rapport d'audit de sécurité automatisé (Spectra) pour le RSSI d'une société cliente.

**VOTRE TON ET STYLE :**
1.  **Professionnel et Factuel :** Vos affirmations sont basées strictement sur les données techniques fournies.
2.  **Non-alarmiste :** Vous êtes un partenaire de confiance. Évitez le vocabulaire de la peur ("catastrophique", "panique"). Utilisez une terminologie standard ("risque critique", "non-conformité", "impact élevé").
3.  **Constructif :** Pour chaque problème, vous envisagez une solution.
4.  **Concis :** Allez à l'essentiel. Style "Audit Industriel".
5.  **Langue :** Français professionnel soutenu.

**VOTRE OBJECTIF :**
Produire des sections de texte prêtes à être insérées dans un document Word final. Ne faites pas de Markdown complexe (pas de tableaux, pas de listes imbriquées complexes), faites des paragraphes clairs.
"""

# -----------------------------------------------------------------------------
# 2. SYNTHÈSE EXÉCUTIVE (STEP 1)
# Génère l'avis global et le résumé des risques majeurs.
# Données en entrée : Statistiques + Top 3 Vulnérabilités.
# -----------------------------------------------------------------------------
PROMPT_EXECUTIVE_SUMMARY = """
Voici les résultats bruts du scan Spectra pour le projet "{project_name}" :

**STATISTIQUES :**
- Total Vulnérabilités : {total_count}
- 🔴 CRITIQUE : {critical_count}
- 🟠 HIGH : {high_count}
- 🔵 MEDIUM : {medium_count}
- 🟢 LOW : {low_count}

**TOP 3 DES RISQUES IDENTIFIÉS (Données techniques) :**
{top_3_risks_text}

**TACHE :**
Rédigez la section "SYNTHÈSE EXÉCUTIVE" en deux parties :

1.  **Avis Global de Sécurité :** Un paragraphe résumant l'état de sécurité général. Indiquez si le projet est "Conforme" ou "Non conforme" et donnez une appréciation globale (ex: "Niveau de risque critique nécessitant une action immédiate").
2.  **Analyse des Risques Majeurs :** Synthétisez en quelques phrases les tendances principales observées dans le Top 3 (ex: "Le risque principal porte sur la gestion des secrets...").

Ne mettez pas de titres, juste les paragraphes.
"""

# -----------------------------------------------------------------------------
# 3. ANALYSE DÉTAILLÉE (STEP 2 - Itératif)
# Génère la description qualitative d'un GROUPE de vulnérabilités (ex: "SQL Injection").
# Données en entrée : Métadonnées d'un type de vulnérabilité.
# -----------------------------------------------------------------------------
PROMPT_VULN_DETAILS = """
Nous analysons une famille de vulnérabilités détectée :

**IDENTITÉ :**
- Titre : {title}
- Catégorie OWASP : {owasp_category}
- Outil de détection : {tool}
- Sévérité : {severity}

**DESCRIPTION TECHNIQUE BRUTE :**
{description}

**TACHE :**
Rédigez les 3 sous-sections suivantes pour le rapport (en texte simple) :

1.  **Description :** Expliquez vulgairement la nature de cette faille pour un décideur technique.
2.  **Impact Business :** Quel est le risque concret pour l'entreprise (ex: Vol de données, Arrêt de service) ?
3.  **Recommandation Générique :** Quelle est la bonne pratique pour corriger ce type de défaut ? (Ne mentionnez pas les fichiers spécifiques ici, cela sera ajouté automatiquement).

Soyez précis et technique mais accessible.
"""

# -----------------------------------------------------------------------------
# 4. CONCLUSION (STEP 3)
# -----------------------------------------------------------------------------
PROMPT_CONCLUSION = """
Basé sur les données précédentes (Total : {total_count}, dont {critical_count} critiques), rédigez une "CONCLUSION ET PLAN D'ACTION" courte.

Proposez une priorisation macroscopique :
- Ce qui doit être fait maintenant (Immédiat).
- Ce qui doit être fait au prochain Sprint (Court terme).
- Une phrase de clôture engageante sur l'intégration de la sécurité continue.

Restez bienveillant et professionnel.
"""
