// @ts-check
for (const button of document.querySelectorAll('button')) {
  button.addEventListener('click', () => {
    const destination = '/__test__/policy-control.html'
    switch (button.textContent) {
      case 'replace':
        location.replace(destination)
        break
      case 'assign':
        location.assign(destination)
        break
      case 'reload':
        location.reload()
        break
      case 'meta': {
        const refresh = document.createElement('meta')
        refresh.httpEquiv = 'refresh'
        refresh.content = `0;url=${destination}`
        document.head.append(refresh)
        break
      }
      case 'back':
        history.back()
        break
      case 'form': {
        const form = document.querySelector('form')
        if (!(form instanceof HTMLFormElement)) throw new Error('Missing navigation form')
        form.submit()
        break
      }
      default:
        throw new Error('Unknown navigation method')
    }
  })
}
