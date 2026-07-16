export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    if (!user?.data?.email) {
      return res.status(401).json({ error: 'Unauthorized' })
    }

    if (typeof req.body.id !== 'string') {
      return res.status(400).json({ error: 'Wrong Params' })
    }

    db.reviewsCollection.update(
      { _id: req.body.id, author: user.data.email },
      { $set: { message: req.body.message } }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        if (result.modified === 0) {
          return res.status(403).json({ error: 'Not allowed' })
        }
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
