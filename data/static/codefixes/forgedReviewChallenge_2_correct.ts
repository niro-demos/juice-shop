export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)

    if (typeof req.body.id !== 'string') {
      res.status(400).json({ error: 'Invalid review id' })
      return
    }

    db.reviewsCollection.update(
      { _id: req.body.id, author: user.data.email },
      { $set: { message: req.body.message } }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        if (result.modified === 0) {
          res.status(404).json({ error: 'Not found' })
          return
        }
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}