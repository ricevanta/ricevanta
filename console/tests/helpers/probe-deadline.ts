import { errors } from 'playwright'

export class ProbeDeadlineError extends Error {}

export async function readBeforeDeadline<T>(
  deadline: number,
  read: (timeout: number) => Promise<T>,
): Promise<T> {
  const timeout = deadline - Date.now()
  if (timeout <= 0) throw new ProbeDeadlineError('Probe read deadline reached')
  try {
    return await read(timeout)
  } catch (error) {
    if (error instanceof errors.TimeoutError) {
      // The action timer can round down. End at the same deadline without another read.
      const remaining = deadline - Date.now()
      if (remaining > 0) await new Promise<void>((resolve) => setTimeout(resolve, remaining))
      throw new ProbeDeadlineError('Probe read deadline reached', { cause: error })
    }
    throw error
  }
}
