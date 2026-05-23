'use client'
import { motion, type HTMLMotionProps } from 'framer-motion'

interface Props extends HTMLMotionProps<'div'> {
  delay?: number
  y?: number
}

export function AnimateIn({ children, delay = 0, y = 22, ...props }: Props) {
  return (
    <motion.div
      initial={{ opacity: 0, y }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-60px' }}
      transition={{ duration: 0.65, delay, ease: [0.22, 1, 0.36, 1] }}
      {...props}
    >
      {children}
    </motion.div>
  )
}
