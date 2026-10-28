"""Self-contained report presentation; no external runtime assets."""

REPORT_SIDEBAR = r"""
<aside class="sidebar" id="sidebar" aria-label="Report and test navigation">
  <div class="sidebar-inner">
    <div class="brand">
      <div class="brand-mark">NF</div>
      <div><h2>Neutron Flux</h2><p>Network validation</p></div>
      <button class="rail-close" type="button" data-close-sidebar>Close</button>
    </div>
    <div class="rail-run">
      <div><strong>Test run</strong><span class="status" id="sideStatus">Partial</span></div>
      <small id="sideStarted"></small>
      <span hidden id="sideRun"></span>
    </div>
    <div class="rail-label">Report</div>
    <nav class="report-navigation" aria-label="Report sections">
      <a href="#view=overview" data-view-link="overview"><span>Run summary</span></a>
      <a href="#view=tests" data-view-link="tests"><span>Tests</span><span class="nav-count" id="navTests">0</span></a>
      <a href="#view=findings" data-view-link="findings"><span>Findings</span><span class="nav-count" id="navFindings">0</span></a>
      <a href="#view=performance" data-view-link="performance"><span>Performance</span><span class="nav-count" id="navPerformance">0</span></a>
      <a href="#view=paths" data-view-link="paths"><span>Technical paths</span><span class="nav-count" id="navPaths">0</span></a>
      <a href="#view=run" data-view-link="run"><span>Run details</span></a>
    </nav>
    <div id="testWorkspace"></div>
    <div class="rail-footer" id="sideVersion"></div>
  </div>
</aside>

"""
