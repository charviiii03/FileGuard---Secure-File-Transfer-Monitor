/* dashboard/static/report_pdf.js
 * FileGuard PDF generation and manual download
 */

'use strict';

document.addEventListener('DOMContentLoaded', function () {
  const generateButton = document.getElementById('btn-generate-pdf');
  const generateLabel = document.getElementById('generate-pdf-label');
  const downloadButton = document.getElementById('btn-download-pdf');
  const reportPreview = document.getElementById('report-pre');
  const reportStatus = document.getElementById('report-status');

  if (!generateButton) {
    console.error('Generate PDF button was not found.');
    return;
  }

  if (!downloadButton) {
    console.error('Download PDF button was not found.');
    return;
  }

  // Keep Download PDF hidden until a report is generated.
  downloadButton.hidden = true;
  downloadButton.style.display = 'none';

  generateButton.addEventListener('click', async function (event) {
    event.preventDefault();

    generateButton.disabled = true;

    if (generateLabel) {
      generateLabel.textContent = 'Generating...';
    }

    downloadButton.hidden = true;
    downloadButton.style.display = 'none';
    downloadButton.removeAttribute('href');

    if (reportStatus) {
      reportStatus.className = 'report-status info';
      reportStatus.textContent = 'Generating PDF report...';
    }

    if (reportPreview) {
      reportPreview.textContent =
        'Generating the latest security report...';
    }

    try {
      const response = await fetch('/api/report/pdf/generate', {
        method: 'POST',
        headers: {
          Accept: 'application/json'
        },
        cache: 'no-store'
      });

      const contentType =
        response.headers.get('content-type') || '';

      if (!contentType.includes('application/json')) {
        const rawResponse = await response.text();

        throw new Error(
          `Server returned HTTP ${response.status}. ` +
          rawResponse.slice(0, 150)
        );
      }

      const data = await response.json();

      if (!response.ok || data.success !== true) {
        throw new Error(
          data.error || 'PDF generation failed.'
        );
      }

      if (!data.download_url) {
        throw new Error(
          'The server did not return a download URL.'
        );
      }

      if (reportPreview) {
        reportPreview.textContent =
          data.report || 'PDF report generated successfully.';
      }

      // Prepare the Download PDF button.
      // This does NOT start the download automatically.
      downloadButton.href = data.download_url;
      downloadButton.download =
        data.filename || 'fileguard_security_report.pdf';

      downloadButton.hidden = false;
      downloadButton.style.display = 'inline-flex';

      if (reportStatus) {
        reportStatus.className = 'report-status success';
        reportStatus.textContent =
          'PDF generated successfully. Click “Download PDF” to save it.';
      }
    } catch (error) {
      console.error('PDF generation error:', error);

      downloadButton.hidden = true;
      downloadButton.style.display = 'none';

      if (reportPreview) {
        reportPreview.textContent =
          'Unable to generate the PDF report.';
      }

      if (reportStatus) {
        reportStatus.className = 'report-status error';
        reportStatus.textContent =
          error.message || 'PDF generation failed.';
      }
    } finally {
      generateButton.disabled = false;

      if (generateLabel) {
        generateLabel.textContent = 'Generate PDF';
      }
    }
  });

  downloadButton.addEventListener('click', function (event) {
    const downloadUrl = downloadButton.getAttribute('href');

    if (!downloadUrl || downloadUrl === '#') {
      event.preventDefault();

      if (reportStatus) {
        reportStatus.className = 'report-status error';
        reportStatus.textContent =
          'Generate the PDF before downloading it.';
      }

      return;
    }

    if (reportStatus) {
      reportStatus.className = 'report-status success';
      reportStatus.textContent = 'Downloading PDF report...';
    }
  });
});