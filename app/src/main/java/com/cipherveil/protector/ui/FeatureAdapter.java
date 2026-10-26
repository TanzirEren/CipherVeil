package com.cipherveil.protector.ui;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import android.widget.CheckBox;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.cipherveil.protector.R;

/**
 * Renders the protection feature matrix. Every row enters with a staggered
 * fade + scale animation to give the "systems booting up" feel.
 */
public class FeatureAdapter extends RecyclerView.Adapter<FeatureAdapter.VH> {

    private final String[] names;
    private final boolean[] checked;
    private final Context ctx;
    private int lastAnimatedPosition = -1;

    public FeatureAdapter(Context ctx, String[] names) {
        this.ctx = ctx;
        this.names = names;
        this.checked = new boolean[names.length];
        for (int i = 0; i < checked.length; i++) checked[i] = true;
    }

    public boolean[] getSelections() {
        return checked;
    }

    @NonNull
    @Override
    public VH onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v = LayoutInflater.from(ctx).inflate(R.layout.item_feature, parent, false);
        return new VH(v);
    }

    @Override
    public void onBindViewHolder(@NonNull VH h, int position) {
        h.name.setText(String.format("%02d  %s", position + 1, names[position]));
        h.box.setChecked(checked[position]);
        h.box.setOnCheckedChangeListener((btn, isChecked) -> checked[position] = isChecked);

        if (position > lastAnimatedPosition) {
            Animation anim = AnimationUtils.loadAnimation(ctx, R.anim.fade_scale_in);
            anim.setStartOffset(position * 45L);
            h.itemView.startAnimation(anim);
            lastAnimatedPosition = position;
        }
    }

    @Override
    public int getItemCount() {
        return names.length;
    }

    static class VH extends RecyclerView.ViewHolder {
        CheckBox box;
        TextView name;

        VH(View v) {
            super(v);
            box = v.findViewById(R.id.chk_feature);
            name = v.findViewById(R.id.txt_feature_name);
        }
    }
}
