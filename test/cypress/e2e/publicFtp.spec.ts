describe('/ftp', () => {
  describe('challenge "confidentialDocument"', () => {
    it('should be able to access file /ftp/acquisitions.md', () => {
      cy.request('/ftp/acquisitions.md')
      cy.expectChallengeSolved({ challenge: 'Confidential Document' })
    })
  })

  describe('challenge "errorHandling"', () => {
    it('should leak information through error message accessing /ftp/easter.egg due to wrong file suffix', () => {
      cy.visit('/ftp/easter.egg', { failOnStatusCode: false })

      cy.get('#stacktrace').then((elements) => {
        // eslint-disable-next-line @typescript-eslint/no-unused-expressions
        expect(!!elements.length).to.be.true
      })
      cy.expectChallengeSolved({ challenge: 'Error Handling' })
    })
  })

  // Regression coverage for TC-471B9F9B: the /ftp file-extension allowlist used
  // to be checked against the raw filename and only afterwards normalized
  // (poison null byte cut off) before the file was actually served, so
  // appending a URL-encoded poison null byte plus an allowed suffix
  // (`%2500.md`) bypassed the allowlist for any file in /ftp regardless of
  // its real extension. Now that the allowlist is evaluated against the same,
  // already-normalized filename that gets served, these requests are
  // rejected with 403 and no longer solve their associated challenges.
  describe('challenge "forgottenBackup"', () => {
    it('is no longer solvable via poison null byte bypass of /ftp/coupons_2013.md.bak', () => {
      cy.request({ url: '/ftp/coupons_2013.md.bak%2500.md', failOnStatusCode: false })
        .its('status').should('eq', 403)
    })
  })

  describe('challenge "forgottenDevBackup"', () => {
    it('is no longer solvable via poison null byte bypass of /ftp/package.json.bak', () => {
      cy.request({ url: '/ftp/package.json.bak%2500.md', failOnStatusCode: false })
        .its('status').should('eq', 403)
    })
  })

  describe('challenge "easterEgg1"', () => {
    it('is no longer solvable via poison null byte bypass of /ftp/eastere.gg', () => {
      cy.request({ url: '/ftp/eastere.gg%2500.md', failOnStatusCode: false })
        .its('status').should('eq', 403)
    })
  })

  describe('challenge "misplacedSiemFileChallenge"', () => {
    it('is no longer solvable via poison null byte bypass of /ftp/suspicious_errors.yml', () => {
      cy.request({ url: '/ftp/suspicious_errors.yml%2500.md', failOnStatusCode: false })
        .its('status').should('eq', 403)
    })
  })

  describe('challenge "nullByteChallenge"', () => {
    it('is no longer solvable via poison null byte bypass of a disallowed file type in /ftp', () => {
      cy.request({ url: '/ftp/encrypt.pyc%2500.md', failOnStatusCode: false })
        .its('status').should('eq', 403)
    })
  })
})
