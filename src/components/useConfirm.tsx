"use client";

import { useCallback, useState, type ReactNode } from "react";
import { Modal } from "@/components/Modal";
import { Button } from "@/components/ui";

type ConfirmOptions = {
  title: string;
  message: ReactNode;
  confirmLabel: string;
  /** Red confirm button, for things that can't be undone. */
  danger?: boolean;
};

/**
 * In-app replacement for window.confirm(). Render `dialog` once, then
 * `if (await confirm({...})) doThing()`.
 */
export function useConfirm() {
  const [request, setRequest] = useState<(ConfirmOptions & { resolve: (ok: boolean) => void }) | null>(null);

  const confirm = useCallback(
    (opts: ConfirmOptions) => new Promise<boolean>((resolve) => setRequest({ ...opts, resolve })),
    [],
  );

  const finish = (ok: boolean) => {
    request?.resolve(ok);
    setRequest(null);
  };

  const dialog = (
    <Modal open={!!request} onClose={() => finish(false)} title={request?.title ?? ""}>
      {request && (
        <div className="flex flex-col gap-5">
          <div className="text-muted">{request.message}</div>
          <div className="flex justify-end gap-2">
            {/* Focus lands on cancel, so a stray Enter doesn't confirm. */}
            <Button type="button" variant="secondary" autoFocus data-autofocus onClick={() => finish(false)}>
              nvm
            </Button>
            <Button type="button" variant={request.danger ? "danger" : "primary"} onClick={() => finish(true)}>
              {request.confirmLabel}
            </Button>
          </div>
        </div>
      )}
    </Modal>
  );

  return [confirm, dialog] as const;
}
