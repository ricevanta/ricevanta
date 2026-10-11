export async function settleDocumentFonts(): Promise<void> {
  // Read ready after layout starts any CSS font loads. Qualify unused faces only once.
  document.body.getBoundingClientRect()
  await document.fonts.ready
}
