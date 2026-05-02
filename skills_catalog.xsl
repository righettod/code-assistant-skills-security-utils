<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

  <xsl:output method="html" version="5.0" encoding="UTF-8" indent="yes"/>

  <!-- ═══════════════════════════════════════════════
       ROOT TEMPLATE
       ═══════════════════════════════════════════════ -->
  <xsl:template match="/">
    <html lang="en">
      <head>
        <meta charset="UTF-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        <title>Claude Skills Catalog</title>
        <style>
          /* ── Reset &amp; base ── */
          *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

          body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                         "Helvetica Neue", Arial, sans-serif;
            background: #0f1117;
            color: #e2e8f0;
            min-height: 100vh;
            padding: 2rem 1rem 4rem;
          }

          /* ── Header ── */
          header {
            text-align: center;
            margin-bottom: 3rem;
          }

          header .badge {
            display: inline-block;
            background: linear-gradient(135deg, #6366f1, #8b5cf6);
            color: #fff;
            font-size: .7rem;
            font-weight: 700;
            letter-spacing: .12em;
            text-transform: uppercase;
            padding: .3rem .85rem;
            border-radius: 999px;
            margin-bottom: .9rem;
          }

          header h1 {
            font-size: clamp(1.8rem, 4vw, 2.8rem);
            font-weight: 800;
            background: linear-gradient(135deg, #a5b4fc 0%, #818cf8 50%, #c4b5fd 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: .5rem;
          }

          header p.subtitle {
            color: #64748b;
            font-size: .95rem;
          }

          /* ── Counter pill ── */
          .skill-count {
            display: inline-flex;
            align-items: center;
            gap: .4rem;
            background: #1e2130;
            border: 1px solid #2d3148;
            border-radius: 999px;
            padding: .35rem 1rem;
            font-size: .82rem;
            color: #94a3b8;
            margin-bottom: 2.5rem;
          }
          .skill-count strong { color: #a5b4fc; }

          /* ── Grid ── */
          .grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            gap: 1.25rem;
            max-width: 1200px;
            margin: 0 auto;
          }

          /* ── Card ── */
          .card {
            background: #161b2e;
            border: 1px solid #1e2440;
            border-radius: 14px;
            padding: 1.5rem 1.6rem 1.4rem;
            display: flex;
            flex-direction: column;
            gap: .85rem;
            transition: transform .18s ease, border-color .18s ease, box-shadow .18s ease;
          }
          .card:hover {
            transform: translateY(-3px);
            border-color: #4f46e5;
            box-shadow: 0 0 0 1px #4f46e540, 0 12px 30px -8px #0000006e;
          }

          /* ── Card header ── */
          .card-header {
            display: flex;
            align-items: flex-start;
            gap: .9rem;
          }

          .icon {
            flex-shrink: 0;
            width: 42px;
            height: 42px;
            border-radius: 10px;
            background: linear-gradient(135deg, #312e81, #4338ca);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
          }

          .card-title {
            font-size: .92rem;
            font-weight: 700;
            color: #c7d2fe;
            letter-spacing: .01em;
            word-break: break-word;
          }

          .card-subtitle {
            font-size: .72rem;
            color: #475569;
            margin-top: .15rem;
            font-family: "SF Mono", "Fira Code", Consolas, monospace;
          }

          /* ── Description ── */
          .card-desc {
            font-size: .84rem;
            line-height: 1.6;
            color: #94a3b8;
            flex: 1;
          }

          /* ── Trigger tag ── */
          .trigger-label {
            font-size: .7rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: .08em;
            color: #475569;
            margin-bottom: .35rem;
          }

          .trigger-text {
            font-size: .78rem;
            color: #64748b;
            font-style: italic;
            line-height: 1.5;
          }

          /* ── Link ── */
          .bundle-link {
            color: #818cf8;
            text-decoration: none;
            font-weight: 500;
          }

          .card-link {
            display: inline-flex;
            align-items: center;
            gap: .4rem;
            font-size: .75rem;
            color: #818cf8;
            text-decoration: none;
            font-weight: 500;
            border-top: 1px solid #1e2440;
            padding-top: .85rem;
            margin-top: auto;
            transition: color .15s;
          }
          .card-link:hover { color: #a5b4fc; }
          .card-link svg { flex-shrink: 0; }

          /* ── Footer ── */
          footer {
            text-align: center;
            margin-top: 3.5rem;
            color: #334155;
            font-size: .78rem;
          }
        </style>
      </head>
      <body>
        <header>
          <div class="badge">Skills Catalog</div>
          <h1>Claude Security Skills</h1>
          <p class="subtitle">Security-focused code-generation skills for Claude Code assistants</p>
          <p class="subtitle"><a class="bundle-link" href="skills.zip" target="_blank" rel="noopener noreferrer">Download the bundle</a></p>
        </header>

        <div style="text-align:center">
          <span class="skill-count">
            <strong><xsl:value-of select="count(available_skills/skill)"/></strong> skills available.
          </span>
        </div>

        <div class="grid">
          <xsl:apply-templates select="available_skills/skill"/>
        </div>

        <footer>
          Generated from the file <a class="bundle-link" href="https://github.com/righettod/code-assistant-skills-security-utils/blob/main/skills_catalog.xml"><code>skills_catalog.xml</code></a>·
        </footer>
      </body>
    </html>
  </xsl:template>

  <!-- ═══════════════════════════════════════════════
       SKILL TEMPLATE
       ═══════════════════════════════════════════════ -->
  <xsl:template match="skill">
    <!-- Pick an emoji icon based on the skill name keywords -->
    <xsl:variable name="skname" select="normalize-space(name)"/>

    <div class="card">
      <div class="card-header">
        <div class="icon">
          <xsl:choose>
            <xsl:when test="contains($skname,'xml')">📄</xsl:when>
            <xsl:when test="contains($skname,'pdf') or contains($skname,'word') or contains($skname,'excel')">📑</xsl:when>
            <xsl:when test="contains($skname,'digest') or contains($skname,'hash')">🔑</xsl:when>
            <xsl:when test="contains($skname,'log')">📋</xsl:when>
            <xsl:when test="contains($skname,'image')">🖼️</xsl:when>
            <xsl:when test="contains($skname,'email')">✉️</xsl:when>
            <xsl:when test="contains($skname,'csv')">📊</xsl:when>
            <xsl:when test="contains($skname,'archive')">📦</xsl:when>
            <xsl:when test="contains($skname,'url')">🌍</xsl:when>
            <xsl:otherwise>🛡️</xsl:otherwise>
          </xsl:choose>
        </div>
        <div>
          <div class="card-title"><xsl:value-of select="$skname"/></div>
          <div class="card-subtitle">skill</div>
        </div>
      </div>

      <!-- Full description -->
      <p class="card-desc">
        <xsl:value-of select="normalize-space(description)"/>
      </p>

      <!-- Link to SKILL.md -->
      <a class="card-link" href="{normalize-space(location)}" target="_blank" rel="noopener noreferrer">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
          <polyline points="15 3 21 3 21 9"/>
          <line x1="10" y1="14" x2="21" y2="3"/>
        </svg>
        View SKILL.md on GitHub
      </a>
    </div>
  </xsl:template>

</xsl:stylesheet>
