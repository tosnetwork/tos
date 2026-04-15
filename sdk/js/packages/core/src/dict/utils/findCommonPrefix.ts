/**
 * Find common prefix among sorted keys.
 */

export function findCommonPrefix(src: string[], startPos: number = 0): string {
    if (src.length === 0) {
        return '';
    }

    let r = src[0]!.slice(startPos);

    for (let i = 1; i < src.length; i++) {
        const s = src[i]!;
        while (s.indexOf(r, startPos) !== startPos) {
            r = r.substring(0, r.length - 1);
            if (r === '') {
                return r;
            }
        }
    }

    return r;
}
